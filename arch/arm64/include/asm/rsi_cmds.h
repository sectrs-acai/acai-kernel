/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#ifndef __ASM_RSI_CMDS_H
#define __ASM_RSI_CMDS_H

#include <linux/arm-smccc.h>

#include <asm/rsi_smc.h>

enum ripas {
	RSI_RIPAS_EMPTY,
	RSI_RIPAS_RAM,
};

enum dev_mem_state {
	RSI_DEV_MEM_UNDELEGATE = 0,
	RSI_DEV_MEM_DELEGATE = 1,
};


static inline unsigned long rsi_get_version(void)
{
	struct arm_smccc_res res;

	arm_smccc_smc(SMC_RSI_ABI_VERSION, 0, 0, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

static inline unsigned long invoke_rsi_fn_smc(unsigned long function_id,
					      unsigned long arg0,
					      unsigned long arg1,
					      unsigned long arg2,
					      unsigned long arg3)
{
	struct arm_smccc_res res;

	arm_smccc_smc(function_id, arg0, arg1, arg2, arg3, 0, 0, 0, &res);
	return res.a0;
}

static inline void invoke_rsi_fn_smc_with_res(unsigned long function_id,
					      unsigned long arg0,
					      unsigned long arg1,
					      unsigned long arg2,
					      unsigned long arg3,
					      struct arm_smccc_res *res)
{
	arm_smccc_smc(function_id, arg0, arg1, arg2, arg3, 0, 0, 0, res);
}

static inline unsigned long rsi_get_realm_config(struct realm_config *cfg)
{
	struct arm_smccc_res res;

	invoke_rsi_fn_smc_with_res(SMC_RSI_REALM_CONFIG, virt_to_phys(cfg), 0, 0, 0, &res);
	return res.a0;
}

static inline unsigned long rsi_set_addr_range_state(phys_addr_t start,
						     phys_addr_t end,
						     enum ripas state,
						     phys_addr_t *top)
{
	struct arm_smccc_res res;

	invoke_rsi_fn_smc_with_res(SMC_RSI_IPA_STATE_SET,
				   start, (end - start), state, 0, &res);

	*top = res.a1;
	return res.a0;
}



/* granule_num: number of 4k pages from start */
static inline unsigned long rsi_set_addr_range_dev_mem(phys_addr_t start,
						       unsigned long granule_num,
						       enum dev_mem_state state)
{
	struct arm_smccc_res res;

	invoke_rsi_fn_smc_with_res(SMC_RSI_DEV_MEM,
				   start, state, granule_num, 0, &res);
	return res.a0;
}

static inline unsigned long rsi_set_addr_dev_mem(phys_addr_t start,
						 enum dev_mem_state state)
{
	struct arm_smccc_res res;

	invoke_rsi_fn_smc_with_res(SMC_RSI_DEV_MEM,
				   start, state, 1, 0, &res);
	return res.a0;
}


static inline unsigned long rsi_claim_device(unsigned long sid)
{
	struct arm_smccc_res res;
	invoke_rsi_fn_smc_with_res(SMC_CLAIM_DEVICE,sid, 0, 0, 0, &res);
	return res.a0;
}

static inline unsigned long rsi_trigger_testengine(unsigned long iova_src,unsigned long iova_dst, unsigned long sid)
{
	struct arm_smccc_res res;
	invoke_rsi_fn_smc_with_res(SMC_TRIGGER_TESTENGINE,iova_src, iova_dst, sid, 0, &res);
	return res.a0;
}
// really ugly
extern int map_pages_from_sid(unsigned int sid, unsigned long pa, unsigned long va, unsigned long num_pages);

static inline unsigned long _map_pages_from_sid(unsigned int sid, unsigned long pa, unsigned long va, unsigned long num_pages){
	return map_pages_from_sid(sid, pa, va, num_pages);
}

#endif
