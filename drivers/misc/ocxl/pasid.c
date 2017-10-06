/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <asm/pnv-ocxl.h>
#include "ocxl_internal.h"

#define DEBUG

/* fxb: I now doubt PASID should be global to the system. We don't
 * really care, they could be unique per SPA, i.e per brick.
 * And it would prevent a bad AFU with a config space requesting
 * more than we can support and preventing other functions to get
 * their PASIDs.
 * To be reworked.
 */

static struct list_head system_range_list;
static struct mutex system_range_list_lock;

struct pasid_range {
	struct list_head list;
	u32 start;
	u32 end;
};

#ifdef DEBUG
static void dump_list(struct list_head *head)
{
	struct pasid_range *cur;

	pr_debug("PASID ranges allocated:\n");
	list_for_each_entry(cur, head, list) {
		pr_debug("Range %d->%d\n", cur->start, cur->end);
	}
}
#endif

static int _pasid_range_alloc(struct list_head *head, struct mutex *lock,
			u32 size, int max_pasid)
{
	struct list_head *pos;
	struct pasid_range *cur, *new;
	int rc, last_end;

	new = kmalloc(sizeof(struct pasid_range), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	mutex_lock(lock);
	pos = head;
	last_end = -1;
	list_for_each_entry(cur, head, list) {
		if ((cur->start - last_end) > size) {
			break;
		}
		last_end = cur->end;
		pos = &cur->list;
	}

	new->start = last_end + 1;
	new->end = new->start + size - 1;

	if (new->end > max_pasid) {
		kfree(new);
		rc = -ENOSPC;
	} else {
		list_add(&new->list, pos);
		rc = new->start;
	}
	mutex_unlock(lock);
#ifdef DEBUG
	dump_list(head);
#endif
	return rc;
}

static void _pasid_range_free(struct list_head *head, struct mutex *lock,
			u32 start, u32 size)
{
	bool found = false;
	struct pasid_range *cur, *tmp;

	mutex_lock(lock);
	list_for_each_entry_safe(cur, tmp, head, list) {
		if (cur->start == start && cur->end == (start + size - 1)) {
			found = true;
			list_del(&cur->list);
			kfree(cur);
			break;
		}
	}
	mutex_unlock(lock);
	WARN_ON(!found);
#ifdef DEBUG
	dump_list(head);
#endif
}

int ocxl_pasid_alloc(u32 size)
{
	return _pasid_range_alloc(&system_range_list, &system_range_list_lock,
				size, pnv_ocxl_get_max_pasid_value());
}

void ocxl_pasid_free(u32 start, u32 size)
{
	return _pasid_range_free(&system_range_list, &system_range_list_lock,
				start, size);

}

int ocxl_pasid_afu_alloc(struct ocxl_fn *fn, u32 size)
{
	int max_pasid;

	if (fn->config.max_pasid_log < 0)
		return -ENOSPC;
	max_pasid = 1 << fn->config.max_pasid_log;
	return _pasid_range_alloc(&fn->pasid_list,
				&fn->pasid_list_lock, size, max_pasid);
}

void ocxl_pasid_afu_free(struct ocxl_fn *fn, u32 start, u32 size)
{
	return _pasid_range_free(&fn->pasid_list,
				&fn->pasid_list_lock, start, size);
}

/* fxb actag prefix */
int ocxl_actag_afu_alloc(struct ocxl_fn *fn, u32 size)
{
	int max_actag;

	max_actag = fn->actag_length;
	return _pasid_range_alloc(&fn->actag_list,
				&fn->actag_list_lock, size, max_actag);
}

void ocxl_actag_afu_free(struct ocxl_fn *fn, u32 start, u32 size)
{
	return _pasid_range_free(&fn->actag_list,
				&fn->actag_list_lock, start, size);
}

int ocxl_pasid_init(void)
{
	INIT_LIST_HEAD(&system_range_list);
	mutex_init(&system_range_list_lock);
	return 0;
}


void ocxl_pasid_exit(void)
{
	struct pasid_range *range, *tmp;

	mutex_lock(&system_range_list_lock);
	list_for_each_entry_safe(range, tmp, &system_range_list, list) {
		kfree(range);
	}
	mutex_unlock(&system_range_list_lock);
}
