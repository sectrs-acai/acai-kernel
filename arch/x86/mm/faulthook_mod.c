/*
 * faulthook-mod allows userspace applications to
 * inject faulthooks and serve them in userspace.
 *
 * see also faulthook.c.
 *
 * abertschi, 2022
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/interrupt.h>
#include <linux/debugfs.h>
#include <linux/kprobes.h>
#include <linux/entry-common.h>
#include <linux/faulthook.h>

struct faulthook_ctrl {
	bool active;
	pid_t pid;
	unsigned long address;
};

#define FAULTHOOK_IOCTL_MAGIC_NUMBER (long)0x3d18

#define FAULTHOOK_IOCTL_CMD_STATUS _IOR(FAULTHOOK_IOCTL_MAGIC_NUMBER, 1, size_t)

#define FAULTHOOK_IOCTL_CMD_HOOK_COMPLETED                                     \
	_IOR(FAULTHOOK_IOCTL_MAGIC_NUMBER, 2, size_t)

#define PTR_FMT "0x%llx"

#define FAULT_STATE_INIT 0
#define FAULT_STATE_CONTINUE_FAULT 1
#define FAULT_STATE_CONTINUE_USER_POLL 2
#define FAULT_STATE_USER_POLL_PROCESSED 3

struct module_ctx {
	struct wait_queue_head poll_waitq; // wait queue for userspace poll
	struct wait_queue_head fault_waitq; // wait queue for faulthook
	struct dentry *debugfs_dir;

	int device_busy_pid;
	bool device_busy;

	atomic_t fault_state; // state machine

	uint64_t target_address;
	int target_pid;


	struct faulthook_probe *probe;
	bool probe_active;


};

struct module_ctx module_ctx;

// static DEFINE_MUTEX(faulthook_mutex);
static DEFINE_SPINLOCK(faulthook_lock);

static inline void notify_continue_fault(void) {
	atomic_set(&module_ctx.fault_state, FAULT_STATE_CONTINUE_FAULT);
	wake_up(&module_ctx.fault_waitq);
}

static void pre_faulthook(struct faulthook_probe *p, struct pt_regs *regs,
			  unsigned long addr)
{
	if (!module_ctx.probe_active || !module_ctx.device_busy) {
		pr_warn("No client is connected."
			"Not serving fault. Skipping request"
			"(addr: " PTR_FMT ", pid: %d)\n",
			addr, p->pid);
		return;
	}

	// local_irq_enable();

	/*
	 * Notify a polling userspace application to serve the fault
	 */
	wake_up_interruptible(&module_ctx.poll_waitq);
	atomic_set(&module_ctx.fault_state, FAULT_STATE_CONTINUE_USER_POLL);

	/*
	 * Pause faulthook until userspace application served the request
	 * */
	wait_event(module_ctx.fault_waitq,
		   atomic_read(&module_ctx.fault_state) ==
			   FAULT_STATE_CONTINUE_FAULT);

	// local_irq_disable();
}

static int register_probe(pid_t pid,
			  unsigned long address,
			  struct faulthook_probe **ret_probe)
{
	int ret;

	struct faulthook_probe *probe =
		kmalloc(sizeof(struct faulthook_probe),
			GFP_KERNEL);

	if (!probe) {
		pr_err("kmalloc failed in ioremap\n");
		return -ENOMEM;
	}

	*probe = (struct faulthook_probe){ .addr = (unsigned long)address,
					   .len = 4096,
					   .pre_handler = pre_faulthook,
					   .pid = pid,
					   .private = &module_ctx };

	ret = register_faulthook_probe(probe);
	if (ret != 0) {
		kfree(probe);
		pr_err("register_faulthook_probe failed\n");
		return ret;
	}
	*ret_probe = probe;
	return 0;
}

static int unregister_probe(void)
{
	pr_info("unregistering faulthook probe\n");
	module_ctx.target_address = 0;
	module_ctx.target_pid = 0;
	module_ctx.probe_active = 0;

	if (module_ctx.probe) {
		unregister_faulthook_probe(module_ctx.probe);
		kfree(module_ctx.probe);
		module_ctx.probe = NULL;
		synchronize_rcu();
	}

	notify_continue_fault();

	return 0;
}

static __poll_t device_poll(struct file *filp,
			    struct poll_table_struct *wait)
{
	__poll_t mask = 0;
	poll_wait(filp, &module_ctx.poll_waitq, wait);

	if (atomic_read(&module_ctx.fault_state)
	    == FAULT_STATE_CONTINUE_USER_POLL) {
		atomic_set(&module_ctx.fault_state,
			   FAULT_STATE_USER_POLL_PROCESSED);

		mask |= POLLIN | POLLRDNORM;
		return mask;

	} else {
		wake_up_interruptible(&module_ctx.fault_waitq);
		return 0;
	}
}

static long device_ioctl_cmd_status(struct file *file, unsigned int ioctl_num,
				    unsigned long ioctl_param)
{
	int ret = 0;
	pr_info("FAULTHOOK_IOCTL_CMD_STATUS\n");

	struct faulthook_ctrl usr;

	ret = copy_from_user(&usr,
			     (void *)ioctl_param,
			     sizeof(struct faulthook_ctrl));
	if (ret) {
		pr_info("copy_from_user failed\n");
		return -EFAULT;
	}

	if (usr.active == 1) {
		if (module_ctx.probe_active) {
			pr_info("A fault hook is already active Releasing old context\n");
			unregister_probe();
		}

		pid_t pid = usr.pid;
		unsigned long address = usr.address;
		struct faulthook_probe *p = NULL;

		int ret = register_probe(pid,
					 address,
					 &p);
		if (ret != 0) {
			pr_err("register_probe failed\n");
			return -EFAULT;
		}
		module_ctx.probe_active = 1;
		module_ctx.probe = p;
		module_ctx.target_pid = pid;
		module_ctx.target_address = address;
	} else {
		unregister_probe();
	}
	return 0;
}

static long device_cmd_hook_complete(struct file *file, unsigned int ioctl_num,
				     unsigned long ioctl_param)
{
	if (module_ctx.probe_active) {
		/* continue serving a pending fault */
		notify_continue_fault();

	} else {
		pr_info("No faulthook is active\n");
	}
	return 0;
}

static long device_ioctl(struct file *file, unsigned int ioctl_num,
			 unsigned long ioctl_param)
{
	switch (ioctl_num) {
	case FAULTHOOK_IOCTL_CMD_STATUS: {
		return device_ioctl_cmd_status(file, ioctl_num, ioctl_param);
	}
	case FAULTHOOK_IOCTL_CMD_HOOK_COMPLETED: {
		return device_cmd_hook_complete(file, ioctl_num, ioctl_param);
	}
	default:
		return -1;
	}
}

static int device_open(struct inode *inode, struct file *file)
{
	pr_info("device_open %d\n", current->pid);

	if (module_ctx.device_busy == true) {
		return -EBUSY;
	}



	module_ctx.device_busy_pid = current->pid;
	module_ctx.device_busy = true;
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	pr_info("device_release %d\n", current->pid);

	/*
         * TODO: If a processed is killed
         * or does not properly clean up we have no longer a valid pid
         * but still an entry with a faulthook.
         * this leads to inconstent state
         *
         * We have to properly clean up even if pid is dead.
         */
	module_ctx.device_busy = false;
	module_ctx.device_busy_pid = -1;

	if (module_ctx.probe_active) {
		unregister_probe();
	}
	return 0;
}

static const struct file_operations device_ops = { .owner = THIS_MODULE,
						   .poll = device_poll,
						   .unlocked_ioctl =
							   device_ioctl,
						   .open = device_open,
						   .release = device_release };

static int register_device(void)
{
	struct dentry *entry, *dir;
	int ret = 0;

	dir = debugfs_create_dir("faulthook", 0);
	if (!dir) {
		pr_alert("failed to create debugfs\n");
		ret = 1;
		goto clean_up;
	}

	entry = debugfs_create_file("hook", 0777, dir, &module_ctx,
				    &device_ops);
	if (!entry) {
		pr_err("failed to create entry\n");
		ret = 1;
		goto clean_up;
	}

	module_ctx.debugfs_dir = dir;
	return 0;

clean_up:
	debugfs_remove_recursive(dir);
	return ret;
}
struct kprobe faulthook_kprobe;

static int kprobe_pre_exit(struct kprobe *p, struct pt_regs *regs)
{
	int i;
	struct faulthook_page *f;
	struct list_head *head;

	pr_info("probe_active: %d, "
		"current pid: %d,"
		"target_pid: %d, "
		"device_pid: %d\n",
		module_ctx.probe_active,
		current->pid,
		module_ctx.target_pid,
		module_ctx.device_busy_pid);

	if (current->pid == module_ctx.device_busy_pid) {
		pr_warn("device driver pid %d "
			"did not release device on exit. cleaning up\n",
			current->pid);
		unregister_probe();
		module_ctx.device_busy_pid = -1;
		module_ctx.device_busy = false;

	} else if (current->pid ==  module_ctx.target_pid) {
		pr_warn("target %d dies cleaning up\n", current->pid);
		unregister_probe();
	}
	return 0;
}

static int register_exit_kprobe(void)
{
	int ret = 0;
	memset(&faulthook_kprobe, 0, sizeof(faulthook_kprobe));
	faulthook_kprobe.pre_handler = kprobe_pre_exit;
	faulthook_kprobe.symbol_name = "do_exit";
	ret = register_kprobe(&faulthook_kprobe);

	if (ret != 0) {
		pr_err("Kprobe register for faulthook failed. "
		       "Faulting processes may leave inconsistent state!\n");
	}
	return ret;
}

static void unregister_exit_krobe(void)
{
	unregister_kprobe(&faulthook_kprobe);
}

static __init int mod_init(void)
{
	pr_info("faulthook_mod_init\n");

	memset(&module_ctx, 0, sizeof(struct module_ctx));
	// module_ctx.lock = __SPIN_LOCK_UNLOCKED(module_ctx.lock);

	init_waitqueue_head(&module_ctx.poll_waitq);
	init_waitqueue_head(&module_ctx.fault_waitq);
	atomic_set(&module_ctx.fault_state, FAULT_STATE_INIT);

	faulthook_init();
	register_exit_kprobe();

	if (register_device() != 0) {
		return -1;
	}
	return 0;
}

static __exit void mod_exit(void)
{
	pr_info("faulthook_mod_exit\n");
	if (module_ctx.probe_active) {
		unregister_probe();
	}
	faulthook_clean();
	unregister_exit_krobe();

	if (module_ctx.debugfs_dir) {
		debugfs_remove_recursive(module_ctx.debugfs_dir);
	}
}

module_init(mod_init) module_exit(mod_exit) MODULE_LICENSE("GPL");