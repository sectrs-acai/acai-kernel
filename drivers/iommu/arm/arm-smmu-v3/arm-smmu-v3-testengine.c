#include <linux/acpi.h>
#include <linux/acpi_iort.h>
#include <linux/bitops.h>
#include <linux/crash_dump.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io-pgtable.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/msi.h>
#include <linux/of.h>
#include <asm/io.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/pci-ats.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <asm/cacheflush.h>

#include "arm-smmu-v3.h"
#include "../../dma-iommu.h"
#include "../../iommu-sva.h"

// needed for configuration.
uintptr_t engine_base_addr;

#define USER_FRAME_START 0x2bfe0000
#define PRIV_FRAME_START 0x2bff0000
#define MAPPING_SIZE        0x20000
#define PRIV_OFFSET (PRIV_FRAME_START-USER_FRAME_START)
#define COPY_SIZE 4096UL * 1
#define NO_SUBSTREAMID	(0xFFFFFFFFU)
#define LOOP_COUNT	(5000U)
#define DEVICE_STREAM_ID 31

#define SMC_MAP_PAGES_ID 0xc40001b4
#define SMC_DELEGATE_PAGE_TO_ROOT 0xc40001b5

/* The test engine supports numerous frames but we only use a few */
#define FRAME_COUNT	(2U)
#define FRAME_SIZE	(0x80U) /* 128 bytes */
#define F_IDX(n)	(n * FRAME_SIZE)

/* Commands supported by SMMUv3TestEngine built into the AEM */
#define ENGINE_NO_FRAME	(0U)
#define ENGINE_HALTED	(1U)

/*
 * ENGINE_MEMCPY: Read and Write transactions
 * ENGINE_RAND48: Only Write transactions: Source address not required
 * ENGINE_SUM64: Only read transactions: Target address not required
 */
#define ENGINE_MEMCPY	(2U)
#define ENGINE_RAND48	(3U)
#define ENGINE_SUM64	(4U)
#define ENGINE_ERROR	(0xFFFFFFFFU)
#define ENGINE_MIS_CFG	(ENGINE_ERROR - 1)

/*
 * Refer to:
 * https://developer.arm.com/documentation/100964/1111-00/Trace-components/SMMUv3TestEngine---trace
 */

/* Offset of various control fields belonging to User Frame */
#define CMD_OFF		(0x0U)
#define UCTRL_OFF	(0x4U)
#define SEED_OFF	(0x24U)
#define BEGIN_OFF	(0x28U)
#define END_CTRL_OFF	(0x30U)
#define STRIDE_OFF	(0x38U)
#define UDATA_OFF	(0x40U)

/* Offset of various control fields belonging to PRIV Frame */
#define PCTRL_OFF		(0x0U)
#define DOWNSTREAM_PORT_OFF	(0x4U)
#define STREAM_ID_OFF		(0x8U)
#define SUBSTREAM_ID_OFF	(0xCU)

extern struct iommu_device *createTestengineEntry(struct arm_smmu_device *smmu);
extern int arm_smmu_attach_testengine(struct iommu_domain *domain,struct arm_smmu_device *smmu, u32 sid);


static inline void mmio_write_32(uintptr_t addr, uint32_t value)
{
	*(volatile uint32_t*)addr = value;
}

static inline void mmio_write32_offset(uintptr_t addr, uint32_t byte_off,
					uint32_t data)
{
	mmio_write_32((uintptr_t)((uint8_t *)addr + byte_off), data);
}

static inline uint32_t mmio_read_32(uintptr_t addr)
{
	return *(volatile uint32_t*)addr;
}

static inline uint32_t mmio_read32_offset(uintptr_t addr, uint32_t byte_off)
{
	return mmio_read_32((uintptr_t)((uint8_t *)addr + byte_off));
}

static inline void mmio_write_64(uintptr_t addr, uint64_t value)
{
	*(volatile uint64_t*)addr = value;
}

static inline void mmio_write64_offset(uintptr_t addr, uint32_t byte_off,
					uint64_t data)
{
	mmio_write_64((uintptr_t)((uint8_t *)addr + byte_off), data);
}

static inline uint64_t mmio_read_64(uintptr_t addr)
{
	return *(volatile uint64_t*)addr;
}


static void do_memcpy(uintptr_t target_phys_addr,uintptr_t source_phys_addr, uint64_t size){
	/* Initiate DMA sequence */
	mmio_write32_offset(engine_base_addr + PRIV_OFFSET, PCTRL_OFF, 0);
	mmio_write32_offset(engine_base_addr + PRIV_OFFSET, DOWNSTREAM_PORT_OFF, 0);
	mmio_write32_offset(engine_base_addr + PRIV_OFFSET, STREAM_ID_OFF, DEVICE_STREAM_ID);
	mmio_write32_offset(engine_base_addr + PRIV_OFFSET, SUBSTREAM_ID_OFF, NO_SUBSTREAMID);

	mmio_write32_offset(engine_base_addr, UCTRL_OFF, 0);
	mmio_write32_offset(engine_base_addr, SEED_OFF, 0);
	mmio_write64_offset(engine_base_addr, BEGIN_OFF, source_phys_addr);
	mmio_write64_offset(engine_base_addr, END_CTRL_OFF, source_phys_addr + size -1ULL);

	/* Legal values for stride: 1 and any multiples of 8 */
	mmio_write64_offset(engine_base_addr, STRIDE_OFF, 1);
	mmio_write64_offset(engine_base_addr, UDATA_OFF, target_phys_addr);

	mmio_write32_offset(engine_base_addr, CMD_OFF, ENGINE_MEMCPY);
	pr_info("SMMUv3TestEngine: Waiting for MEMCPY completion for frame: %llx\n",(uint64_t)source_phys_addr);
	// Memory barrier, so no compiler reordering.
	barrier();
	flush_cache_vmap(engine_base_addr,MAPPING_SIZE);
}

int testengine_copy_and_check_status(uintptr_t target_phys_addr,uintptr_t source_phys_addr, uint64_t size, bool check){
	uint64_t attempts = 0U,source_virt_addr,target_virt_addr;
	uint32_t status;
	bool failed = false;

	pr_info("copy from 0x%lx, to 0x%lx 0x%llx bytes",source_phys_addr,target_phys_addr, size);
	do_memcpy(target_phys_addr,source_phys_addr,size);
		/*
	 * It is guaranteed that a read of "cmd" fields after writing to it will
	 * immediately return ENGINE_FRAME_MISCONFIGURED if the command was
	 * invalid.
	*/
	if (mmio_read32_offset(engine_base_addr, CMD_OFF) ==
	    ENGINE_MIS_CFG) {
		pr_err("SMMUv3TestEngine: Misconfigured for frame: %llu\n", (uint64_t)target_phys_addr);
		return false;
	}
	/* Wait for mem copy to be complete */
	while (attempts++ < LOOP_COUNT) {
		pr_info("loop count");
		status = mmio_read32_offset(engine_base_addr, CMD_OFF);
		if (status == ENGINE_HALTED) {
			break;
		} else if (status == ENGINE_ERROR) {
			pr_err("SMMUv3: Test failed, status ENGINE_ERROR\n");
			return false;
		}
		/*
			 * TODO: Introduce a small delay here to make sure the
			 * CPU memory accesses do not starve the interconnect
			 * due to continuous polling.
		 */
		 // * BENE: DONE
		 cond_resched();
	}

	if (attempts == LOOP_COUNT) {
		pr_err("SMMUv3: Test LOOP_COUNT, will continue checking memory\n");
	}
	source_virt_addr = (uint64_t)phys_to_virt(source_phys_addr);
	target_virt_addr = (uint64_t)phys_to_virt(target_phys_addr);
	/* Compare source and destination memory locations for data */
	if (!check)
		return !failed;

	for (int i = 0U; i < (size / 8U); i++) {
		if (mmio_read_64(source_virt_addr + 8 * i) != mmio_read_64(target_virt_addr + 8 * i)) {
			pr_info("SMMUv3: Mem copy failed: %llx\n", target_virt_addr + 8 * i);
			failed = true;
		}
	}
	if(!failed){
		pr_info("SMMUv3: TESTs WERE SUCCESSFULL");
	}

	return !failed;
}

bool run_tests(struct io_pgtable_ops *ops)
{
	uint64_t data[] = { ULL(0xBAADFEEDCEEBDAAF), ULL(0x0123456776543210) };
	uintptr_t source_virt_addr = (uintptr_t)kzalloc(COPY_SIZE, GFP_DMA);
	uintptr_t target_virt_addr = (uintptr_t)kzalloc(COPY_SIZE, GFP_DMA);
	phys_addr_t source_phys_addr;
	phys_addr_t target_phys_addr;
	uint32_t ret = 0;
	size_t mapped_source = 0;
	size_t mapped_target = 0;


	// Not really needed, since we are doing s2 translations, 
	// but we can easily use this to generate 'unique' IOVAs.
	source_phys_addr = virt_to_phys((void *)source_virt_addr);
	target_phys_addr = virt_to_phys((void *)target_virt_addr);

	ret = arm_smccc_get_version();
	pr_info("smmuv3: smc version %x",ret);

	pr_info("mapping %lx bytes of memory for dma", COPY_SIZE);


	/* 
	 * ------------------ LIMITATIONS ------------------
	 * This code can only map up to 512 pages (i.e. fill the current page table). We must check the return value  
	 * and the MAPPED variable and call the map_pages function again if we want to map more than this amount of memory.
	*/
	pr_info("smmuv3 map dma source pages phys: %llx to IOVA: %llx", (u64)source_phys_addr,(u64)source_phys_addr);
	ret = ops->map_pages(ops,source_phys_addr,source_phys_addr,4096,COPY_SIZE/4096,(IOMMU_READ | IOMMU_WRITE),GFP_DMA | __GFP_ZERO,&mapped_source);
	if(ret){
		pr_info("smmuv3: failed to map dma source pages");
	}

	pr_info("smmuv3 map dma target pages phys: %llx to IOVA: %llx", (u64)target_phys_addr,(u64)target_phys_addr);
	ret = ops->map_pages(ops,target_phys_addr,target_phys_addr,4096,COPY_SIZE/4096,(IOMMU_READ | IOMMU_WRITE),GFP_DMA | __GFP_ZERO,&mapped_target);
	if(ret){
		pr_info("smmuv3: failed to map dma target pages");
	}

	/* Write pre-determined content to source pages */
	for (int i = 0U; i < (COPY_SIZE / 8U); i++) {
		mmio_write64_offset(source_virt_addr, i * 8, data[i%2]);
	}
	// flush caches to phys memory.
	flush_cache_vmap(source_virt_addr,COPY_SIZE);
	// Memory barrier, so no compiler reordering.
	barrier();

	return testengine_copy_and_check_status(target_phys_addr,source_phys_addr, COPY_SIZE, true);
}

// Should be sufficent, since we only need it to derive the iommu_domain and iommu from it.
/* static struct device *get_device_from_number(unsigned int bus, unsigned int devfn){
	struct pci_dev *dev = NULL;
	for_each_pci_dev(dev) {
		if (dev->bus->number == bus && dev->devfn == devfn){
			return &dev->dev;
		}
	}
	return &dev->dev;
} */


static int arm_smmu_testengine_device_probe(struct platform_device *pdev)
{
	pr_info("testengine probe %s", pdev->name);
	return 0;
}


void testengine_initcall(struct arm_smmu_domain *smmu_domain, struct arm_smmu_device *smmu){

	/* struct pci_dev *stub_pci_device;
  	stub_pci_device = getRandomPCIeDevice();
	if (stub_pci_device != NULL){
		pr_info("found PCIe device smmu testengine");
	}else {
		pr_info("did not found PCIe smmu testengine");
	} */

	engine_base_addr = (uintptr_t)ioremap(USER_FRAME_START, MAPPING_SIZE);
	pr_info("smmuv3: mapped region to %llx", (uint64_t)engine_base_addr);
	run_tests(smmu_domain->pgtbl_ops);
	pr_info("smmuv3: ran tests");
	return;
}


static int arm_smmu_testengine_device_remove(struct platform_device *pdev)
{
	pr_info("testengine remove");
	return 0;
}

static void arm_smmu_testengine_device_shutdown(struct platform_device *pdev)
{
	pr_info("testengine shutdown");
}

static const struct of_device_id arm_smmu_testdriver_of_match[] = {
	{
		.compatible = "arm,smmuv3-testengine",
	},
	{},
};
MODULE_DEVICE_TABLE(of, arm_smmu_testdriver_of_match);

static void arm_smmu_driver_unregister(struct platform_driver *drv)
{
	pr_info("unregister testengine");
	platform_driver_unregister(drv);
}

static struct platform_driver arm_smmu_testengine_driver = {
	.driver	= {
		.name			= "smmuv3-testengine",
		.of_match_table		= arm_smmu_testdriver_of_match,
	},
	.probe	= arm_smmu_testengine_device_probe,
	.remove	= arm_smmu_testengine_device_remove,
	.shutdown = arm_smmu_testengine_device_shutdown,
};
module_driver(arm_smmu_testengine_driver, platform_driver_register,
	      arm_smmu_driver_unregister);

MODULE_DESCRIPTION("testdriver for the SMMUv3-testengine");
MODULE_AUTHOR("Benedict Schlueter <benedict.schlueter@inf.ethz.ch>");
MODULE_ALIAS("platform:arm-smmu-v3-testengine");
MODULE_LICENSE("GPL v2");