/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _OCXL_INTERNAL_H_
#define _OCXL_INTERNAL_H_

#include <linux/cdev.h>
#include <linux/list.h>
#include <misc/ocxl.h>

#define to_ocxl_function(d) container_of(d, struct ocxl_fn, dev)
#define to_ocxl_afu(d) container_of(d, struct ocxl_afu, dev)

extern struct pci_driver ocxl_pci_driver;


struct ocxl_fn {
	struct device dev;
	struct ocxl_fn_config config;
	struct list_head afu_list;
	int pasid_base;
	int actag_base;
	int actag_length;
	struct mutex pasid_list_lock;
	struct list_head pasid_list;
	struct mutex actag_list_lock;
	struct list_head actag_list;
	void *link_token;
};

struct ocxl_afu {
	struct ocxl_fn *fn;
	struct list_head list;
	struct device dev;
	struct cdev cdev;
	struct ocxl_afu_config config;
	int pasid_base;
	int pasid_count; /* opened contexts */
	int pasid_max; /* maximum number of contexts */
	int actag_base;
	int actag_length;
	struct mutex contexts_lock;
	struct idr contexts_idr;
	struct mutex afu_control_lock;
	u64 global_mmio_start;
	u64 pp_mmio_start;
	struct bin_attribute attr_global_mmio;
};

enum ocxl_context_status {
	CLOSED,
	OPENED,
	ATTACHED,
};

struct ocxl_context {
	struct ocxl_afu *afu;
	int pasid;
	struct mutex status_mutex;
	enum ocxl_context_status status;
	struct address_space *mapping;
	struct mutex mapping_lock;
};

extern struct ocxl_afu *ocxl_afu_get(struct ocxl_afu *afu);
extern void ocxl_afu_put(struct ocxl_afu *afu);

extern int ocxl_create_cdev(struct ocxl_afu *afu);
extern void ocxl_destroy_cdev(struct ocxl_afu *afu);
extern int ocxl_register_afu(struct ocxl_afu *afu);
extern void ocxl_unregister_afu(struct ocxl_afu *afu);
extern int ocxl_register_function(struct ocxl_fn *fn);

extern int ocxl_file_init(void);
extern void ocxl_file_exit(void);

extern int ocxl_pasid_alloc(u32 size);
extern void ocxl_pasid_free(u32 start, u32 size);
extern int ocxl_pasid_afu_alloc(struct ocxl_fn *fn, u32 size);
extern void ocxl_pasid_afu_free(struct ocxl_fn *fn, u32 start, u32 size);
extern int ocxl_actag_afu_alloc(struct ocxl_fn *fn, u32 size);
extern void ocxl_actag_afu_free(struct ocxl_fn *fn, u32 start, u32 size);
extern int ocxl_pasid_init(void);
extern void ocxl_pasid_exit(void);

extern struct ocxl_context *ocxl_context_alloc(void);
extern int ocxl_context_init(struct ocxl_context *ctx, struct ocxl_afu *afu,
			struct address_space *mapping);
extern int ocxl_context_attach(struct ocxl_context *ctx, u64 amr);
extern int ocxl_context_iomap(struct ocxl_context *ctx,
			struct vm_area_struct *vma);
extern int ocxl_context_detach(struct ocxl_context *ctx);
extern void ocxl_context_detach_all(struct ocxl_afu *afu);
extern void ocxl_context_free(struct ocxl_context *ctx);

extern int ocxl_sysfs_add_afu(struct ocxl_afu *afu);
extern void ocxl_sysfs_remove_afu(struct ocxl_afu *afu);

#endif /* _OCXL_INTERNAL_H_ */
