// SPDX-License-Identifier: GPL-2.0

/*
 * Faulthook is a fork of kmmio.c.
 * Unlike kmmio.c, faulthook allows pagefault hooks into userspace addresses of
 * a process. Most things including the single stepping ideas are reused.
 * The fault handling logic differs in terms of how we disarm a page:
 * We disarm a page on a fault and execute a pre-handler *before* we enable single stepping.
 * This allows a pre-handler to access the page and read-out data.
 *
 * abertschi, 2022
 *
 */

/*
 * Benfit many code from kprobes
 * (C) 2002 Louis Zhuang <louis.zhuang@intel.com>.
 *     2007 Alexander Eichner
 *     2008 Pekka Paalanen <pq@iki.fi>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define STRINGIZING(x) #x
#define STR(x) STRINGIZING(x)
#define FILE_LINE __FILE__ ":" STR(__LINE__)
#define HERE pr_err(FILE_LINE)

#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/hash.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/preempt.h>
#include <linux/percpu.h>
#include <linux/kdebug.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <linux/errno.h>
#include <asm/debugreg.h>
#include <linux/faulthook.h>
#include <linux/cpu.h>

#define FAULTHOOK_PAGE_HASH_BITS 4
#define FAULTHOOK_PAGE_TABLE_SIZE (1 << FAULTHOOK_PAGE_HASH_BITS)
#define PTR_FMT "0x%llx"

struct faulthook_page {
    struct list_head list;
    struct faulthook_page *release_next;
    unsigned long addr; /* the requested address */
    pteval_t old_presence; /* page presence prior to arming */
    bool armed;

    pid_t pid;

    /*
     * Number of times this page has been registered as a part
     * of a probe. If zero, page is disarmed and this may be freed.
     * Used only by writers (RCU) and post_faulthook_handler().
     * Protected by faulthook_lock, when linked into faulthook_page_table.
     */
    int count;

    bool scheduled_for_release;
};

struct faulthook_delayed_release {
    struct rcu_head rcu;
    struct faulthook_page *release_list;
};

struct faulthook_context {
    struct faulthook_page *fpage;
    struct faulthook_probe *probe;
    unsigned long saved_flags;
    unsigned long addr;
    int active;
};

static DEFINE_SPINLOCK(faulthook_lock);

/* Protected by faulthook_lock */
unsigned int faulthook_count;

/* Read-protected by RCU, write-protected by faulthook_lock. */
/* buckets of list containing faulthook_page entries */
static struct list_head faulting_pages[FAULTHOOK_PAGE_TABLE_SIZE];
static LIST_HEAD(faulthook_probes);

static inline struct task_struct *get_task_by_pid(pid_t pid)
{
    struct task_struct *task;
    bool found;
    rcu_read_lock();
    for_each_process (task) {
        if (task->pid==pid) {
            found = true;
            pr_info("found %d\n: %s", pid, task->comm);
            break;
        }
    }
    rcu_read_unlock();
    return task;
}

static inline struct mm_struct *get_mm(size_t pid)
{
    struct task_struct *task;
    struct pid *vpid;

    /* Find mm */
    task = current;
    if (pid!=0) {
        vpid = find_vpid(pid);
        if (!vpid)
            return NULL;
        task = pid_task(vpid, PIDTYPE_PID);
        if (!task)
            return NULL;
    }
    if (task->mm) {
        return task->mm;
    } else {
        return task->active_mm;
    }
    return NULL;
}

static struct list_head *faulthook_get_page_list(unsigned long addr, pid_t pid)
{
    unsigned int l;
    pte_t * pte = lookup_address_in_mm(get_mm(pid), addr, &l);

    if (!pte) {
        pr_err("pte not found\n");
        return NULL;
    }
    addr &= page_level_mask(l);

    return &faulting_pages[hash_long(addr, FAULTHOOK_PAGE_HASH_BITS)];
}

/* Accessed per-cpu */
static DEFINE_PER_CPU(struct faulthook_context, faulthook_ctx);

/* Get the faulthook at this addr (if any). You must be holding RCU read lock. */
static struct faulthook_probe *get_faulthook_probe(unsigned long addr,
                                                   pid_t pid
)
{
    struct faulthook_probe *p;
    list_for_each_entry_rcu (p, &faulthook_probes, list) {
        if (p->pid==pid && addr >= p->addr &&
                addr < (p->addr + p->len))
            return p;
    }
    return NULL;
}

/* You must be holding RCU read lock. */
static struct faulthook_page *get_faulthook_page(unsigned long addr, pid_t pid)
{
    struct list_head *head;
    struct faulthook_page *f;
    unsigned int l;
    pte_t * pte = lookup_address_in_mm(get_mm(pid), addr, &l);

    if (!pte) {
        pr_warn("no pte found for addr " PTR_FMT "in pid %d\n", addr,
                pid);
        return NULL;
    }

    addr &= page_level_mask(l);
    head = faulthook_get_page_list(addr, pid);
    list_for_each_entry_rcu (f, head, list) {
        if (f->addr==addr && f->pid==pid) {
            return f;
        }
    }
    return NULL;
}

static void clear_pmd_presence(pmd_t *pmd, bool clear, pmdval_t *old)
{
    pmd_t new_pmd;
    pmdval_t v = pmd_val(*pmd);
    if (clear) {
        *old = v;
        new_pmd = pmd_mkinvalid(*pmd);
    } else {
        /* Presume this has been called with clear==true previously */
        new_pmd = __pmd(*old);
    }
    set_pmd(pmd, new_pmd);
}

static void clear_pte_presence(pte_t *pte, bool clear, pteval_t *old)
{
    pteval_t v = pte_val(*pte);
    if (clear) {
        *old = v;
        /* Nothing should care about address */
        pte_clear(&init_mm, 0, pte);
    } else {
        /* Presume this has been called with clear==true previously */
        set_pte_atomic(pte, __pte(*old));
    }
}

static int clear_page_presence(struct faulthook_page *f, bool clear)
{
    unsigned int level;
    pte_t * pte = lookup_address_in_mm(get_mm(f->pid), f->addr, &level);

    if (!pte) {
        pr_err("no pte for addr 0x%08lx\n", f->addr);
        return -1;
    }

    switch (level) {
        case PG_LEVEL_2M:
            clear_pmd_presence((pmd_t *) pte, clear, &f->old_presence);
            break;
        case PG_LEVEL_4K:
            clear_pte_presence(pte, clear, &f->old_presence);
            break;
        default:
            pr_err("unexpected page level 0x%x.\n", level);
            return -1;
    }

    flush_tlb_one_kernel(f->addr);
    return 0;
}

/*
 * Mark the given page as not present. Access to it will trigger a fault.
 *
 * Struct faulthook_fault_page is protected by RCU and faulthook_lock, but the
 * protection is ignored here. RCU read lock is assumed held, so the struct
 * will not disappear unexpectedly. Furthermore, the caller must guarantee,
 * that double arming the same virtual address (page) cannot occur.
 *
 * Double disarming on the other hand is allowed, and may occur when a fault
 * and mmiotrace shutdown happen simultaneously.
 */
static int arm_page(struct faulthook_page *f)
{
    int ret;
    WARN_ONCE(f->armed, KERN_ERR pr_fmt("faulthook page already armed.\n"));
    if (f->armed) {
        pr_warn("double-arm: addr 0x%08lx, ref %d, old %d\n", f->addr,
                f->count, !!f->old_presence);
    }
    ret = clear_page_presence(f, true);
    WARN_ONCE(ret < 0,
              KERN_ERR pr_fmt("arming at 0x%08lx failed, pid %d\n"),
              f->addr, f->pid);
    f->armed = true;
    return ret;
}

/** Restore the given page to saved presence state. */
static void disarm_page(struct faulthook_page *f)
{
    int ret = clear_page_presence(f, false);
    WARN_ONCE(ret < 0, KERN_ERR "faulthook disarming at 0x%08lx failed.\n",
              f->addr);
    f->armed = false;
}

/*
 * This is being called from do_page_fault().
 *
 * We may be in an interrupt or a critical section. Also prefecthing may
 * trigger a page fault. We may be in the middle of process switch.
 * We cannot take any locks, because we could be executing especially
 * within a faulthook critical section.
 *
 * Local interrupts are disabled, so preemption cannot happen.
 * Do not enable interrupts, do not sleep, and watch out for other CPUs.
 */
/*
 * Interrupts are disabled on entry as trap3 is an interrupt gate
 * and they remain disabled throughout this function.
 */
int faulthook_handler(struct pt_regs *regs, unsigned long addr, pid_t pid)
{
    struct faulthook_context *ctx;
    struct faulthook_page *faultpage;
    struct faulthook_probe *probe;
    int ret = 0; /* default to fault not handled */
    unsigned long page_base = addr;
    unsigned int l;

    pte_t * pte = lookup_address_in_mm(get_mm(pid), addr, &l);
    if (!pte) {
        return -EINVAL;
    }

    page_base &= page_level_mask(l);

    pr_info("faulthook_handler on cpu %d addr " PTR_FMT "\n", smp_processor_id(), addr);

    /*
     * Preemption is now disabled to prevent process switch during
     * single stepping. We can only handle one active faulthook trace
     * per cpu, so ensure that we finish it before something else
     * gets to run. We also hold the RCU read lock over single
     * stepping to avoid looking up the probe and faulthook_fault_page
     * again.
     */
    preempt_disable();
    rcu_read_lock();

    faultpage = get_faulthook_page(page_base, pid);
    if (!faultpage) {
        /*
         * Either this page fault is not caused by faulthook, or
         * another CPU just pulled the faulthook probe from under
         * our feet. The latter case should not be possible.
         */
        goto no_faulthook;
    }

    ctx = this_cpu_ptr(&faulthook_ctx);
    if (ctx->active) {
        if (page_base==ctx->addr) {
            /*
             * A second fault on the same page means some other
             * condition needs handling by do_page_fault(), the
             * page really not being present is the most common.
             */
            pr_debug("secondary hit for 0x%08lx CPU %d.\n", addr,
                     smp_processor_id());

            if (!faultpage->old_presence)
                pr_info("unexpected secondary hit for address 0x%08lx on CPU %d.\n",
                        addr, smp_processor_id());
        } else {
            /*
             * Prevent overwriting already in-flight context.
             * This should not happen, let's hope disarming at
             * least prevents a panic.
             */
            pr_emerg(
                    "recursive probe hit on CPU %d, for address 0x%08lx. Ignoring.\n",
                    smp_processor_id(), addr);
            pr_emerg("previous hit was at 0x%08lx.\n", ctx->addr);
            disarm_page(faultpage);
        }
        goto no_faulthook;
    }

    /* Now we set present bit */
    disarm_page(faultpage);
    probe = get_faulthook_probe(page_base, pid);

    rcu_read_unlock();
    preempt_enable_no_resched();

    /*
     * Preemt is allowed again and we released rcu lock.
     * We now execution handler code
     * and upon completion enable single stepping.
     */
    if (probe && probe->pre_handler) {
        probe->pre_handler(probe, regs, addr);
    }

    ctx = this_cpu_ptr(&faulthook_ctx);
    preempt_disable();
    rcu_read_lock();

    // ctx->active++;
    ctx->fpage = faultpage;
    ctx->probe = probe;
    ctx->saved_flags = (regs->flags & (X86_EFLAGS_TF | X86_EFLAGS_IF));
    ctx->addr = page_base;

    /*
     * Enable single-stepping and disable interrupts for the faulting
     * context. Local interrupts must not get enabled during stepping.
     */
    regs->flags |= X86_EFLAGS_TF;
    regs->flags &= ~X86_EFLAGS_IF;

    /*
     * If another cpu accesses the same page while we are stepping,
     * the access will not be caught. It will simply succeed and the
     * only downside is we lose the event. If this becomes a problem,
     * the user should drop to single cpu before tracing.
     */

    return 1; /* fault handled */

    no_faulthook:
    rcu_read_unlock();
    preempt_enable_no_resched();
    return ret;
}

/*
 * Interrupts are disabled on entry as trap1 is an interrupt gate
 * and they remain disabled throughout this function.
 * This must always get called as the pair to faulthook_handler().
 */
static int faulthook_post_handler(unsigned long condition, struct pt_regs *regs)
{
    int ret = 0;
    struct faulthook_context *ctx = this_cpu_ptr(&faulthook_ctx);

#if 0
    if (!ctx->active) {
        /*
         * debug traps without an active context are due to either
         * something external causing them (f.e. using a debugger while
         * mmio tracing enabled), or erroneous behaviour
         */
        pr_warn("unexpected debug trap on CPU %d.\n",
                smp_processor_id());
        goto out;
    }
#endif

    if (ctx->probe && ctx->probe->post_handler)
        ctx->probe->post_handler(ctx->probe, condition, regs);

    /* Prevent racing against release_faulthook_fault_page(). */
    spin_lock(&faulthook_lock);
    if (ctx->fpage->count)
        arm_page(ctx->fpage);
    spin_unlock(&faulthook_lock);

    regs->flags &= ~X86_EFLAGS_TF;
    regs->flags |= ctx->saved_flags;

    /* These were acquired in faulthook_handler(). */
    //ctx->active--;
    //BUG_ON(ctx->active);
    rcu_read_unlock();
    preempt_enable_no_resched();

    /*
     * if somebody else is singlestepping across a probe point, flags
     * will have TF set, in which case, continue the remaining processing
     * of do_debug, as if this is not a probe hit.
     */
    if (!(regs->flags & X86_EFLAGS_TF))
        ret = 1;
    out:
    return ret;
}

/* You must be holding faulthook_lock. */
static int add_faulthook_page(unsigned long addr, pid_t pid)
{
    struct faulthook_page *f;
    f = get_faulthook_page(addr, pid);
    if (f) {
        if (!f->count) {
            arm_page(f);
        }
        f->count++;
        return 0;
    }
    f = kzalloc(sizeof(*f), GFP_ATOMIC);
    if (!f) {
        return -1;
    }

    f->count = 1;
    f->addr = addr;
    f->pid = pid;

    if (arm_page(f)) {
        kfree(f);
        return -1;
    }

    list_add_rcu(&f->list, faulthook_get_page_list(f->addr, f->pid));
    return 0;
}

/* You must be holding faulthook_lock. */
static void release_fault_page(unsigned long addr, pid_t pid,
                               struct faulthook_page **release_list
)
{
    struct faulthook_page *f;

    f = get_faulthook_page(addr, pid);
    if (!f) {
        return;
    }

    f->count--;
    BUG_ON(f->count < 0);
    if (!f->count) {
        disarm_page(f);
        if (!f->scheduled_for_release) {
            f->release_next = *release_list;
            *release_list = f;
            f->scheduled_for_release = true;
        }
    }
}

static int pin_pages(struct faulthook_probe *p)
{
    // pin_user_pages_remote(get_mm(p->pid))
    return 0;
}

/*
 * With page-unaligned ioremaps, one or two armed pages may contain
 * addresses from outside the intended mapping. Events for these addresses
 * are currently silently dropped. The events may result only from programming
 * mistakes by accessing addresses before the beginning or past the end of a
 * mapping.
 */
int register_faulthook_probe(struct faulthook_probe *p)
{
    unsigned long flags;
    int ret = 0;
    unsigned long size = 0;
    unsigned long addr = p->addr & PAGE_MASK;
    const unsigned long size_lim = p->len + (p->addr & ~PAGE_MASK);
    unsigned int l;
    pte_t * pte;

    pr_info("registering faulthook trace " PTR_FMT "for pid %d\n", p->addr,
            p->pid);
    spin_lock_irqsave(&faulthook_lock, flags);

#if 0
    // TODO: Do we have to pin the page?
    if (pin_pages(p)) {
        ret = -EINVAL;
        goto out;
    }
#endif

    if (get_faulthook_probe(addr, p->pid)) {
        pr_err("Faulthook already exists\n");
        ret = -EEXIST;
        goto out;
    }

    pte = lookup_address_in_mm(get_mm(p->pid), addr, &l);
    if (!pte) {
        pr_info(PTR_FMT "not found in pid %d\n", addr, p->pid);
        ret = -EINVAL;
        goto out;
    }

    faulthook_count++;
    list_add_rcu(&p->list, &faulthook_probes);

    while (size < size_lim) {
        if (add_faulthook_page(addr + size, p->pid)) {
            pr_err("Unable to set page fault.\n");
        }
        size += page_level_size(l);
    }
    out:
    spin_unlock_irqrestore(&faulthook_lock, flags);
    /*
     * XXX: What should I do here?
     * Here was a call to global_flush_tlb(), but it does not exist
     * anymore. It seems it's not needed after all.
     */
    // TODO: Flush tlb?
    return ret;
}

EXPORT_SYMBOL(register_faulthook_probe);

static void rcu_free_fault_pages(struct rcu_head *head)
{
    struct faulthook_delayed_release *dr =
            container_of(head, struct faulthook_delayed_release, rcu);
    struct faulthook_page *f = dr->release_list;
    while (f) {
        struct faulthook_page *next = f->release_next;
        BUG_ON(f->count);
        kfree(f);
        f = next;
    }
    kfree(dr);
    pr_info("rcu_free_fault_pages\n");
}

static void remove_fault_pages(struct rcu_head *head)
{
    struct faulthook_delayed_release *dr =
            container_of(head, struct faulthook_delayed_release, rcu);
    struct faulthook_page *f = dr->release_list;
    struct faulthook_page **prevp = &dr->release_list;
    unsigned long flags;

    spin_lock_irqsave(&faulthook_lock, flags);
    while (f) {
        if (!f->count) {
            list_del_rcu(&f->list);
            prevp = &f->release_next;
        } else {
            *prevp = f->release_next;
            f->release_next = NULL;
            f->scheduled_for_release = false;
        }
        f = *prevp;
    }
    spin_unlock_irqrestore(&faulthook_lock, flags);

    /* This is the real RCU destroy call. */
    call_rcu(&dr->rcu, rcu_free_fault_pages);
}

/*
 * Remove a faulthook probe. You have to synchronize_rcu() before you can be
 * sure that the callbacks will not be called anymore. Only after that
 * you may actually release your struct faulthook_probe.
 *
 * Unregistering a faulthook fault page has three steps:
 * 1. release_faulthook_fault_page()
 *    Disarm the page, wait a grace period to let all faults finish.
 * 2. remove_faulthook_fault_pages()
 *    Remove the pages from faulthook_page_table.
 * 3. rcu_free_faulthook_fault_pages()
 *    Actually free the faulthook_fault_page structs as with RCU.
 */
void unregister_faulthook_probe(struct faulthook_probe *p)
{
    unsigned long flags;
    unsigned long size = 0;
    unsigned long addr = p->addr & PAGE_MASK;
    const unsigned long size_lim = p->len + (p->addr & ~PAGE_MASK);
    struct faulthook_page *release_list = NULL;
    struct faulthook_delayed_release *drelease;
    unsigned int l;
    pte_t * pte;
    pr_info("unregistering trace 0x%llx for pid %d\n", p->addr, p->pid);

    pte = lookup_address_in_mm(get_mm(p->pid), addr, &l);
    if (!pte) {
        pr_err("addr " PTR_FMT " not found in pid %d\n", p->addr,
               p->pid);
        return;
    }

    spin_lock_irqsave(&faulthook_lock, flags);
    while (size < size_lim) {
        release_fault_page(addr + size, p->pid, &release_list);
        size += page_level_size(l);
    }
    list_del_rcu(&p->list);
    faulthook_count--;
    spin_unlock_irqrestore(&faulthook_lock, flags);

    if (!release_list) {
        return;
    }

    drelease = kmalloc(sizeof(*drelease), GFP_ATOMIC);
    if (!drelease) {
        pr_crit("leaking faulthook_fault_page objects.\n");
        return;
    }
    drelease->release_list = release_list;

    /*
     * This is not really RCU here. We have just disarmed a set of
     * pages so that they cannot trigger page faults anymore. However,
     * we cannot remove the pages from faulthook_page_table,
     * because a probe hit might be in flight on another CPU. The
     * pages are collected into a list, and they will be removed from
     * faulthook_page_table when it is certain that no probe hit related to
     * these pages can be in flight. RCU grace period sounds like a
     * good choice.
     *
     * If we removed the pages too early, faulthook page fault handler might
     * not find the respective faulthook_fault_page and determine it's not
     * a faulthook fault, when it actually is. This would lead to madness.
     */
    pr_info("unregister end\n");
    call_rcu(&drelease->rcu, remove_fault_pages);
}

EXPORT_SYMBOL(unregister_faulthook_probe);

static int die_notifier(struct notifier_block *nb, unsigned long val,
                        void *args
)
{
    struct die_args *arg = args;
    unsigned long *dr6_p = (unsigned long *) ERR_PTR(arg->err);

    if (val==DIE_DEBUG && (*dr6_p & DR_STEP))
        if (faulthook_post_handler(*dr6_p, arg->regs)==1) {
            /*
             * Reset the BS bit in dr6 (pointed by args->err) to
             * denote completion of processing
             */
            *dr6_p &= ~DR_STEP;
            return NOTIFY_STOP;
        }

    return NOTIFY_DONE;
}

static struct notifier_block nb_die = {.notifier_call = die_notifier};


#ifdef CONFIG_HOTPLUG_CPU
static cpumask_var_t downed_cpus;

static void enter_uniprocessor(void)
{
	int cpu;
	int err;

	if (!cpumask_available(downed_cpus) &&
	    !alloc_cpumask_var(&downed_cpus, GFP_KERNEL)) {
		pr_notice("Failed to allocate mask\n");
		goto out;
	}

	get_online_cpus();
	cpumask_copy(downed_cpus, cpu_online_mask);
	cpumask_clear_cpu(cpumask_first(cpu_online_mask), downed_cpus);
	if (num_online_cpus() > 1)
		pr_notice("Disabling non-boot CPUs...\n");
	put_online_cpus();

	for_each_cpu(cpu, downed_cpus) {
		err = remove_cpu(cpu);
		if (!err)
			pr_info("CPU%d is down.\n", cpu);
		else
			pr_err("Error taking CPU%d down: %d\n", cpu, err);
	}
out:
	if (num_online_cpus() > 1)
		pr_warn("multiple CPUs still online, may miss events.\n");
}

static void leave_uniprocessor(void)
{
	int cpu;
	int err;

	if (!cpumask_available(downed_cpus) || cpumask_weight(downed_cpus) == 0)
		return;
	pr_notice("Re-enabling CPUs...\n");
	for_each_cpu(cpu, downed_cpus) {
		err = add_cpu(cpu);
		if (!err)
			pr_info("enabled CPU%d.\n", cpu);
		else
			pr_err("cannot re-enable CPU%d: %d\n", cpu, err);
	}
}

#else /* !CONFIG_HOTPLUG_CPU */
static void enter_uniprocessor(void)
{
    if (num_online_cpus() > 1)
	pr_warn("multiple CPUs are online, may miss events. "
		"Suggest booting with maxcpus=1 kernel argument.\n");
}

static void leave_uniprocessor(void)
{
}
#endif

int faulthook_init(void)
{
    // Reset per cpu variables
    enter_uniprocessor();
    leave_uniprocessor();
    int i;
    for (i = 0; i < FAULTHOOK_PAGE_TABLE_SIZE; i++) {
	INIT_LIST_HEAD(&faulting_pages[i]);
    }

    return register_die_notifier(&nb_die);
}

void faulthook_clean(void)
{
    int i;

    unregister_die_notifier(&nb_die);
    for (i = 0; i < FAULTHOOK_PAGE_TABLE_SIZE; i++) {
	WARN_ONCE(
		!list_empty(&faulting_pages[i]), KERN_ERR
		"faulthook_page_table not empty at cleanup, any further tracing will leak memory.\n");
    }
}


#if 0
struct kprobe faulthook_kprobe;
static int kprobe_pre_exit(struct kprobe *p, struct pt_regs *regs)
{
    int i;
    struct faulthook_page *f;
    struct list_head *head;

    for (i = 0; i < FAULTHOOK_PAGE_TABLE_SIZE; i++) {
        head = &faulting_pages[i];
        list_for_each_entry_rcu (f, head, list) {
            if (f->pid == current->pid) {
                pr_info("pid %d exists while still having faulthook registered. Cleaning up.\n",
                        f->pid);
                unregister_faulthook_probe(f);
                synchronize_rcu();
            }
        }
    }
    return 0;
}

static int register_exit_kprobe(void) {
    int ret = 0;
    memset(&faulthook_kprobe, 0, sizeof(faulthook_kprobe));
    faulthook_kprobe.pre_handler = kprobe_pre_exit;
    faulthook_kprobe.symbol_name = "do_exit";
    ret = register_kprobe(&faulthook_kprobe);

    if (ret!=0) {
        pr_err("Kprobe register for faulthook failed. "
               "Faulting processes may leave inconsistent state!\n");
    }
    return ret;
}

static void unregister_exit_krobe(void) {
    unregister_kprobe(&faulthook_kprobe);
}

#endif