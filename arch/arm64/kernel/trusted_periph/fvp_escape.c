#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/cache.h>
#include <linux/screen_info.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/root_dev.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/efi.h>
#include <linux/psci.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <asm/acpi.h>
#include <asm/fixmap.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/daifflags.h>
#include <asm/elf.h>
#include <asm/cpufeature.h>
#include <asm/cpu_ops.h>
#include <asm/kasan.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <asm/efi.h>
#include <asm/xen/hypervisor.h>
#include <asm/mmu_context.h>
#include <asm/trusted_periph/fvp_escape.h>
#include <asm/trusted_periph/fvp_escape_setup.h>
#include <linux/init.h>

#define MIN(a, b) (a < b ? a : b)
#define WAIT_1SEC()                                                            \
	do {                                                                   \
		volatile unsigned long _c;                                     \
		for (_c = 0; _c < (1 << 26); _c++) {                           \
		}                                                              \
	} while (0)

/* The chunk of memory reseved for the escape buffer */
#define RESERVE_AREA (3000L * PAGE_SIZE)

/* escape buffer */
unsigned long *fvp_escape_page = NULL;
EXPORT_SYMBOL(fvp_escape_page);

/* escape buffer size */
unsigned long fvp_escape_size = 0;
EXPORT_SYMBOL(fvp_escape_size);

/*
 * TODO: Merge fvp_escape_off and CONFIG_FVP_ESCAPE into single function
 *       to test for status. Code currently tests for CONFIG_FVP_ESCAPE
 *       in most places apart from actual escape tagging.
 */
early_param_on_off("fvp_escape_on",
		   "fvp_escape_off",
		   fvp_escape_status,
		   CONFIG_FVP_ESCAPE);

static int fvp_escape_wait __initdata;
static int __init fvp_escape_wait_setup(char *str)
{
	fvp_escape_wait = 1;
	return 0;
}
early_param("fvp_escape_wait", fvp_escape_wait_setup);

/*
 * Tag all empty pages such that we can map them on the host (FVP host)
 * for a lookup vaddr host <-> paddr fvp
 * XXX: This approach does not cover the already used pages.
 *      We lose around 32MB of DRAM, used by early kernel datastructs.
 *      If this is not enough we may implement tagging in bootloader.
 */
void __meminit init_fvp_escape(void)
{
	int ret = 0;
	const unsigned long max_tries = 12;
	struct fvp_escape_setup_struct *escape = NULL;
	struct fvp_escape_setup_struct *addr_tag = NULL;
	u64 escape_pa, touched, untouched, i, addr;
	phys_addr_t start, end;

	pr_info("fvp_escape_status: %d\n", fvp_escape_status);
	if (!fvp_escape_status) {
		return;
	}

	touched = 0;
	untouched = 0;
	pr_info("fvp escape PFN escape mapping: collecting pages\n");
	pr_info("total dram range: %llx-%llx\n",
		memblock_start_of_DRAM(), memblock_end_of_DRAM());

	for_each_mem_range(i, &start, &end) {
		for (addr = start;
		     addr < end;
		     addr += PAGE_SIZE) {
			addr_tag = (struct fvp_escape_setup_struct *)__va(addr);
			if (!memblock_is_reserved(addr)) {
				touched++;
				addr_tag->ctrl_magic = FVP_CONTROL_MAGIC;
				addr_tag->addr_tag = addr >> PAGE_SHIFT;
			} else {
				poison_region(addr, addr + PAGE_SIZE);
				untouched++;
			}
		}
	}

	/*
	 * Reserve memory region at the end of DRAM
	 * not to interfere with mappings of other startup code
	 */
	for_each_mem_range(i, &start, &end) {
		for (addr = end - PAGE_SIZE - RESERVE_AREA;
		     addr >= start;
		     addr -= PAGE_SIZE) {
			addr_tag = (struct fvp_escape_setup_struct *)__va(addr);
			if (!memblock_is_region_reserved(addr, RESERVE_AREA)) {
				escape = addr_tag;
				break;
			}
		}
	}

	if (escape == NULL) {
		pr_err("No free region found for fvp escape of size: %lx\n",
		       RESERVE_AREA);
		BUG();
	}

	pr_info("fvp escape: PFN escape mapping: "
		"touched: %lld, untouched: %lld\n",
		touched,
		untouched);

	pr_info("fvp escape: magic page pfn=%lx\n", escape->addr_tag);

	escape->escape_magic = FVP_ESCAPE_MAGIC;
	escape->escape_turn = fvp_escape_setup_turn_guest;
	escape->action = fvp_escape_setup_action_addr_mapping;
	escape->data_size = sizeof(unsigned long);
	*((unsigned long *)escape->data) = RESERVE_AREA;

	for (i = 0; (i < max_tries || fvp_escape_wait); i++) {
		escape->escape_hook = i; /* escape */

		pr_info("Please launch userspace manager to exchange "
			"pfn escape mapping (%ld/%ld)\n",
			i + 1, max_tries);

		switch (escape->action) {
		case fvp_escape_setup_action_addr_mapping_success:
		case fvp_escape_setup_action_continue_guest: {
			goto fvp_stop_waiting;
			break;
		}
		case fvp_escape_setup_action_wait_guest: {
			while (escape->action ==
			       fvp_escape_setup_action_wait_guest) {
				pr_info("fvp escape: "
					"waiting for go from host\n");
				WAIT_1SEC();
			}
			break;
		}
		default:
		}
		WAIT_1SEC();
	}

fvp_stop_waiting:
	escape->escape_turn = fvp_escape_setup_turn_guest;
	if (escape->action == fvp_escape_setup_action_addr_mapping_success) {
		pr_info("fvp escape: addr mapping success\n");
		fvp_escape_page = (unsigned long *)escape;
		fvp_escape_size = RESERVE_AREA;
		escape_pa = (escape->addr_tag) << PAGE_SHIFT;
		pr_info("fvp escape: reserving 0x%lx+0x%lx\n",
			escape_pa,
			RESERVE_AREA);

		ret = memblock_remove(escape_pa, RESERVE_AREA);
		if (ret != 0) {
			pr_info("fvp escape: memblock_remove failed for "
				"0x%lx+0x%lx\n", escape_pa, RESERVE_AREA);
		}
	} else {
		pr_info("fvp escape: addr mapping unsuccessful\n");
		/*
		 * undo traces, mapping unfruitful
		 */
		for_each_mem_range(i, &start, &end) {
			for (addr = start;
			     addr < end;
			     addr += PAGE_SIZE) {
				addr_tag = (struct fvp_escape_setup_struct *)__va(addr);
				if (!memblock_is_reserved(addr)) {
					addr_tag->ctrl_magic = 0;
					addr_tag->addr_tag = 0;
				}
			}
		}
	}
}
