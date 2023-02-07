/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FAULTHOOK_H
#define _LINUX_FAULTHOOK_H

#include <linux/types.h>
#include <linux/list.h>

struct faulthook_probe;
struct pt_regs;

typedef void (*faulthook_pre_handler_t)(struct faulthook_probe *,
				struct pt_regs *, unsigned long addr);
typedef void (*faulthook_post_handler_t)(struct faulthook_probe *,
				unsigned long condition, struct pt_regs *);

struct faulthook_probe {
	/* internal list: */
	struct list_head	list;
	/* start location of the probe point: */
	unsigned long		addr;


	pid_t                   pid;
	/* length of the probe region: */
	unsigned long		len;

	/* do not fault on read */
	int allow_read;

	/* Called before addr is executed: */
	faulthook_pre_handler_t pre_handler;
	/* Called after addr is executed: */
	faulthook_post_handler_t post_handler;

	/* during probing we have to pin the pid to a single core */
	int pin_to_core;

	void			*private;
};

extern unsigned int faulthook_count;

extern int register_faulthook_probe(struct faulthook_probe *p);
extern void unregister_faulthook_probe(struct faulthook_probe *p);
extern int faulthook_init(void);
extern void faulthook_clean(void);

#ifdef CONFIG_FAULTHOOK
/* kmmio is active by some kmmio_probes? */
static inline int is_faulthook_active(void)
{
	return faulthook_count;
}

/* Called from page fault handler. */
extern int faulthook_handler(struct pt_regs *regs, unsigned long addr, pid_t pid);

#else /* !CONFIG_FAULTHOOK: */
static inline int is_faulthook_active(void)
{
	return 0;
}

static inline int faulthook_handler(struct pt_regs *regs, unsigned long addr, pid_t pid)
{
	return 0;
}
#endif /* !CONFIG_FAULTHOOK */

#endif /* _LINUX_FAULTHOOK_H */
