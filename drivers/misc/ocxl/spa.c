/*
 * Copyright 2017 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/sched/mm.h>
#include <linux/mutex.h>
#include <linux/mmu_context.h>
#include <asm/copro.h>
#include <asm/pnv-ocxl.h>
#include <misc/ocxl.h>
#include "trace.h"


#define SPA_PASID_BITS		15
#define SPA_PASID_MAX		((1 << SPA_PASID_BITS) - 1)
#define SPA_PE_MASK		SPA_PASID_MAX
#define SPA_SPA_SIZE_LOG	22 /* Each SPA is 4 Mb */

#define SPA_CFG_SF		(1ull << (63-0))
#define SPA_CFG_TA		(1ull << (63-1))
#define SPA_CFG_HV		(1ull << (63-3))
#define SPA_CFG_UV		(1ull << (63-4))
#define SPA_CFG_XLAT_hpt	(0ull << (63-6)) /* Hashed page table (HPT) mode */
#define SPA_CFG_XLAT_roh	(2ull << (63-6)) /* Radix on HPT mode */
#define SPA_CFG_XLAT_ror	(3ull << (63-6)) /* Radix on Radix mode */
#define SPA_CFG_PR		(1ull << (63-49))
#define SPA_CFG_TC		(1ull << (63-54))
#define SPA_CFG_DR		(1ull << (63-59))

#define SPA_XSL_TF		(1ull << (63-3))  /* Translation fault */
#define SPA_XSL_S		(1ull << (63-38)) /* Store operation */

#define SPA_PE_VALID		0x80000000

/*
 * A opencapi link can be used be by several PCI functions. We have
 * one link per device slot.
 *
 * A linked list of opencapi links should suffice, as there's a
 * limited number of opencapi slot on the system.
 */
struct spa {
	struct ocxl_process_element *spa_mem;
	int spa_order;
	struct mutex spa_lock;
	struct radix_tree_root rt; /* Radix tree for context lookup */
	char *irq_name;
	int virq;
	void *irq_mmio[4]; /* dsisr, dar, tfc, pe_handle, in that order */
	/*
	 * The following field are used by the memory fault
	 * interrupt handler. We can only have one interrupt at a
	 * time. The NPU won't raise another interrupt until the
	 * previous one has been ack'd by writing to the TFC register
	 */
	struct work_struct fault_work;
	u64 pe;
	u64 dsisr;
	u64 dar;
	struct mm_struct *fault_mm;
};

struct link {
	struct list_head list;
	struct kref ref;
	int domain;
	int bus;
	int dev;
	struct spa *spa;
	void *platform_data;
};
static struct list_head links_list = LIST_HEAD_INIT(links_list);
static DEFINE_MUTEX(links_list_lock);

enum xsl_response {
	CONTINUE,
	ADDRESS_ERROR,
	RESTART,
};


static void read_irq(struct spa *spa, u64 *dsisr, u64 *dar, u64 *pe)
{
	u64 reg;

	*dsisr = in_be64(spa->irq_mmio[0]);
	*dar = in_be64(spa->irq_mmio[1]);
	reg = in_be64(spa->irq_mmio[3]);
	*pe = reg & SPA_PE_MASK;
}

static void ack_irq(struct spa *spa, enum xsl_response r)
{
	u64 reg = 0;

	/* continue is not supported */
	if (r == RESTART)
		reg = PPC_BIT(31);
	else if (r == ADDRESS_ERROR)
		reg = PPC_BIT(30);
	else
		WARN(1, "Invalid irq response %d\n", r);

	if (reg) {
		trace_ocxl_fault_ack(spa->spa_mem, spa->pe, spa->dsisr,
				spa->dar, reg);
		out_be64(spa->irq_mmio[2], reg);
	}
}

static void handle_page_fault_bh(struct work_struct *fault_work)
{
	unsigned int flt = 0;
	unsigned long access, flags, inv_flags = 0;
	enum xsl_response r;
	struct spa *spa = container_of(fault_work, struct spa, fault_work);
	int rc;

	/*
	 * We need to release a reference on the mm whenever exiting this
	 * function (taken in the memory fault interrupt handler)
	 */
	rc = copro_handle_mm_fault(spa->fault_mm, spa->dar, spa->dsisr,
				&flt);
	if (rc) {
		pr_debug("copro_handle_mm_fault failed: %d\n", rc);
		r = ADDRESS_ERROR;
		goto ack;
	}

	if (!radix_enabled()) {
		/*
		 * update_mmu_cache() will not have loaded the hash
		 * since current->trap is not a 0x400 or 0x300, so
		 * just call hash_page_mm() here.
		 */
		access = _PAGE_PRESENT | _PAGE_READ;
		if (spa->dsisr & SPA_XSL_S)
			access |= _PAGE_WRITE;

		if (REGION_ID(spa->dar) != USER_REGION_ID)
			access |= _PAGE_PRIVILEGED;

		local_irq_save(flags);
		hash_page_mm(spa->fault_mm, spa->dar, access, 0x300,
			inv_flags);
		local_irq_restore(flags);
	}
	r = RESTART;
ack:
	mmdrop(spa->fault_mm);
	ack_irq(spa, r);
}

static irqreturn_t xsl_fault_handler(int irq, void *data)
{
	struct link *link = (struct link *) data;
	struct spa *spa = link->spa;
	u64 dsisr, dar, pe_handle;
	struct mm_struct *mm;
	struct ocxl_process_element *pe;
	int lpid, pid, tid;

	read_irq(spa, &dsisr, &dar, &pe_handle);
	trace_ocxl_fault(spa->spa_mem, pe_handle, dsisr, dar, -1);

	WARN_ON(pe_handle > SPA_PE_MASK);
	pe = spa->spa_mem + pe_handle;
	lpid = be32_to_cpu(pe->lpid);
	pid = be32_to_cpu(pe->pid);
	tid = be32_to_cpu(pe->tid);
	/* We could be reading all null values here if the PE is being
	 * removed while an interrupt kicks in. It's not supposed to
	 * happen if the driver notified the AFU to terminate the
	 * PASID, and the AFU waited for pending operations before
	 * acknowledging. But even if it happens, we won't find a
	 * memory context below and fail silently, so it should be ok.
	 */
	if (!(dsisr & SPA_XSL_TF)) {
		WARN(1, "Invalid xsl interrupt fault register %#llx\n", dsisr);
		ack_irq(spa, ADDRESS_ERROR);
		return IRQ_HANDLED;
	}

	rcu_read_lock();
	mm = radix_tree_lookup(&spa->rt, pe_handle);
	if (!mm) {
		/*
		 * Could only happen if the driver didn't notify the
		 * AFU about PASID termination before removing the PE,
		 * or the AFU didn't wait for all memory access to
		 * have completed.
		 *
		 * Either way, we fail early, but we shouldn't log an
		 * error message, as it is a valid (if unexpected)
		 * scenario
		 */
		rcu_read_unlock();
		pr_debug("Unknown context for xsl interrupt\n");
		ack_irq(spa, ADDRESS_ERROR);
		return IRQ_HANDLED;
	}
	WARN_ON(mm->context.id != pid);
	mmgrab(mm);
	rcu_read_unlock();

	spa->pe = pe_handle;
	spa->dar = dar;
	spa->dsisr = dsisr;
	spa->fault_mm = mm; /* mm count is released by bottom half */
	schedule_work(&spa->fault_work);
	return IRQ_HANDLED;
}

static void unmap_irq_registers(struct spa *spa)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (spa->irq_mmio[i])
			iounmap(spa->irq_mmio[i]);
	}
}

static int map_irq_registers(struct pci_dev *dev, struct spa *spa)
{
	u64 reg;
	int i, rc;

	for (i = 0; i < 4; i++) {
		/* fxb should be moved to platform code */
		rc = of_property_read_u64_index(dev->dev.of_node,
						"ibm,opal-xsl-mmio", i, &reg);
		if (rc)
			goto err;
		spa->irq_mmio[i] = ioremap(reg, 8);
		if (!spa->irq_mmio[i]) {
			rc = -EINVAL;
			goto err;
		}
	}
	return 0;

err:
	dev_err(&dev->dev, "Can't map xsl mmio registers\n");
	unmap_irq_registers(spa);
	return rc;
}


static int setup_xsl_irq(struct pci_dev *dev, struct link *link)
{
	struct spa *spa = link->spa;
	int rc;
	int hwirq;

	/* fxb should be moved to platform code */
	rc = of_property_read_u32(dev->dev.of_node, "ibm,opal-xsl-irq",
				&hwirq);
	if (rc) {
		dev_err(&dev->dev, "Can't find xsl interrupt for device\n");
		return rc;
	}

	rc = map_irq_registers(dev, spa);
	if (rc)
		return rc;

	spa->irq_name = kasprintf(GFP_KERNEL, "ocxl-xsl-%x-%x-%x",
				link->domain, link->bus, link->dev);
	if (!spa->irq_name) {
		unmap_irq_registers(spa);
		dev_err(&dev->dev, "Can't allocate name for xsl interrupt\n");
		return -ENOMEM;
	}

	spa->virq = irq_create_mapping(NULL, hwirq);
	if (!spa->virq) {
		kfree(spa->irq_name);
		unmap_irq_registers(spa);
		dev_err(&dev->dev,
			"irq_create_mapping failed for translation interrupt\n");
		return -EINVAL;
	}

	dev_dbg(&dev->dev, "hwirq %d mapped to virq %d\n", hwirq, spa->virq);

	rc = request_irq(spa->virq, xsl_fault_handler, 0, spa->irq_name,
			link);
	if (rc) {
		irq_dispose_mapping(spa->virq);
		kfree(spa->irq_name);
		unmap_irq_registers(spa);
		dev_err(&dev->dev,
			"request_irq failed for translation interrupt: %d\n",
			rc);
		return -EINVAL;
	}
	return 0;
}

static void release_xsl_irq(struct link *link)
{
	struct spa *spa = link->spa;

	if (spa->virq) {
		free_irq(spa->virq, link);
		irq_dispose_mapping(spa->virq);
	}
	kfree(spa->irq_name);
	unmap_irq_registers(spa);
}

static int alloc_spa(struct pci_dev *dev, struct link *link)
{
	struct spa *spa;

	spa = kzalloc(sizeof(struct spa), GFP_KERNEL);
	if (!spa)
		return -ENOMEM;

	mutex_init(&spa->spa_lock);
	INIT_RADIX_TREE(&spa->rt, GFP_KERNEL);
	INIT_WORK(&spa->fault_work, handle_page_fault_bh);

	spa->spa_order = SPA_SPA_SIZE_LOG - PAGE_SHIFT;
	spa->spa_mem = (struct ocxl_process_element *)
		__get_free_pages(GFP_KERNEL | __GFP_ZERO, spa->spa_order);
	if (!spa->spa_mem) {
		dev_err(&dev->dev, "Can't allocate Shared Process Area\n");
		kfree(spa);
		return -ENOMEM;
	}
	pr_debug("Allocated SPA for %x:%x:%x at %p\n", link->domain, link->bus,
		link->dev, spa->spa_mem);

	link->spa = spa;
	return 0;
}

static void free_spa(struct link *link)
{
	struct spa *spa = link->spa;

	pr_debug("Freeing SPA for %x:%x:%x\n", link->domain, link->bus,
		link->dev);

	if (spa && spa->spa_mem) {
		free_pages((unsigned long) spa->spa_mem, spa->spa_order);
		kfree(spa);
		link->spa = NULL;
	}
}

static int alloc_link(struct pci_dev *dev, struct link **out_link)
{
	struct link *link;
	int rc;

	link = kzalloc(sizeof(struct link), GFP_KERNEL);
	if (!link)
		return -ENOMEM;

	kref_init(&link->ref);
	link->domain = pci_domain_nr(dev->bus);
	link->bus = dev->bus->number;
	link->dev = PCI_SLOT(dev->devfn);

	rc = alloc_spa(dev, link);
	if (rc) {
		kfree(link);
		return rc;
	}

	rc = setup_xsl_irq(dev, link);
	if (rc) {
		free_spa(link);
		kfree(link);
		return rc;
	}

	/* platform specific hook */
	rc = pnv_ocxl_spa_setup(dev, link->spa->spa_mem, &link->platform_data);
	if (rc) {
		release_xsl_irq(link);
		free_spa(link);
		kfree(link);
		return rc;
	}

	*out_link = link;
	return 0;
}

static void free_link(struct link *link)
{
	release_xsl_irq(link);
	free_spa(link);
	kfree(link);
}

int ocxl_spa_setup(struct pci_dev *dev, void **token)
{
	int rc = 0;
	struct link *link;

	mutex_lock(&links_list_lock);
	list_for_each_entry(link, &links_list, list) {
		/* The functions of a device all share the same link */
		if (link->domain == pci_domain_nr(dev->bus) &&
			link->bus == dev->bus->number &&
			link->dev == PCI_SLOT(dev->devfn)) {
			kref_get(&link->ref);
			*token = link;
			goto unlock;
		}
	}
	rc = alloc_link(dev, &link);
	if (rc)
		goto unlock;

	list_add(&link->list, &links_list);
	*token = link;
unlock:
	mutex_unlock(&links_list_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ocxl_spa_setup);

static void release_xsl(struct kref *ref)
{
	struct link *link = container_of(ref, struct link, ref);

	list_del(&link->list);
	/* call platform code before releasing data */
	pnv_ocxl_spa_release(link->platform_data);
	free_link(link);
}

void ocxl_spa_release(struct pci_dev *dev, void *token)
{
	struct link *link = (struct link *) token;

	mutex_lock(&links_list_lock);
	kref_put(&link->ref, release_xsl);
	mutex_unlock(&links_list_lock);
}
EXPORT_SYMBOL_GPL(ocxl_spa_release);

static u64 calculate_cfg_state(bool kernel)
{
	u64 state;

	state = SPA_CFG_DR;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		state |= SPA_CFG_TC;
	if (radix_enabled())
		state |= SPA_CFG_XLAT_ror;
	else
		state |= SPA_CFG_XLAT_hpt;
	state |= SPA_CFG_HV;
	if (kernel) {
		if (mfmsr() & MSR_SF)
			state |= SPA_CFG_SF;
	} else {
		state |= SPA_CFG_PR;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			state |= SPA_CFG_SF;
	}
	return state;
}

int ocxl_spa_add_pe(void *token, int pasid, u32 pidr, u32 tidr, u64 amr,
		struct mm_struct *mm)
{
	struct link *link = (struct link *) token;
	struct spa *spa = link->spa;
	struct ocxl_process_element *pe;
	int pe_handle, rc = 0;

	BUILD_BUG_ON(sizeof(struct ocxl_process_element) != 128);
	if (pasid > SPA_PASID_MAX)
		return -EINVAL;

	mutex_lock(&spa->spa_lock);
	pe_handle = pasid & SPA_PE_MASK;
	pe = spa->spa_mem + pe_handle;

	if (pe->software_state) {
		rc = -EBUSY;
		goto unlock;
	}

	memset(pe, 0, sizeof(struct ocxl_process_element));
	pe->config_state = cpu_to_be64(calculate_cfg_state(pidr == 0));
	pe->lpid = cpu_to_be32(mfspr(SPRN_LPID));
	pe->pid = cpu_to_be32(pidr);
	pe->tid = cpu_to_be32(tidr);
	pe->amr = cpu_to_be64(amr);
	pe->software_state = cpu_to_be32(SPA_PE_VALID);

	mm_context_add_copro(mm);
	/*
	 * Barrier is to make sure PE is visible before it has a
	 * chance of being used. It also helps with the global TLBI
	 * invalidation
	 */
	smp_mb();
	radix_tree_insert(&spa->rt, pe_handle, mm);

	/*
	 * The mm must stay valid for as long as the device uses it. We
	 * lower the count when the context is removed from the SPA.
	 *
	 * We grab mm_count (and not mm_users), as we don't want to
	 * end up in a circular dependency if a process mmaps its
	 * mmio, therefore incrementing the file ref count when
	 * calling mmap(), and forgets to unmap before exiting. In
	 * that scenario, when the kernel handles the death of the
	 * process, the file is not cleaned because unmap was not
	 * called, and the mm wouldn't be freed because we would still
	 * have a reference on mm_users. Incrementing mm_count solves
	 * the problem.
	 */
	mmgrab(mm);
	trace_ocxl_context_add(current->pid, spa->spa_mem, pasid, pidr, tidr);
unlock:
	mutex_unlock(&spa->spa_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ocxl_spa_add_pe);

int ocxl_spa_remove_pe(struct pci_dev *dev, void *token, int pasid)
{
	struct link *link = (struct link *) token;
	struct spa *spa = link->spa;
	struct ocxl_process_element *pe;
	struct mm_struct *mm;
	int pe_handle, rc;

	if (pasid > SPA_PASID_MAX)
		return -EINVAL;

	/*
	 * About synchronization with our memory fault handler:
	 *
	 * Before removing the PE, the driver is supposed to have
	 * notified the AFU, which should have cleaned up and make
	 * sure the PASID is no longer in use, including pending
	 * interrupts. However, there's no way to be sure...
	 *
	 * We clear the PE and remove the context from our radix
	 * tree. From that point on, any new interrupt for that
	 * context will fail silently, which is ok. As mentioned
	 * above, that's not expected, but it could happen if the
	 * driver or AFU didn't do the right thing.
	 *
	 * There could still be a bottom half running, but we don't
	 * need to wait/flush, as it is managing a reference count on
	 * the mm it reads from the radix tree.
	 */
	pe_handle = pasid & SPA_PE_MASK;
	pe = spa->spa_mem + pe_handle;

	mutex_lock(&spa->spa_lock);

	if (!(pe->software_state & cpu_to_be32(SPA_PE_VALID))) {
		rc = -EINVAL;
		goto unlock;
	}

	trace_ocxl_context_remove(current->pid, spa->spa_mem, pasid,
				be32_to_cpu(pe->pid), be32_to_cpu(pe->tid));

	memset(pe, 0, sizeof(struct ocxl_process_element));
	/*
	 * Add a barrier to make sure the order of operation is right
	 */
	mb();

	/*
	 * hook to platform code
	 * On powerpc, the entry needs to be cleared from the context
	 * cache of the NPU.
	 */
	rc = pnv_ocxl_spa_remove_pe(link->platform_data, pe_handle);
	WARN_ON(rc);

	mm = radix_tree_delete(&spa->rt, pe_handle);
	if (!mm) {
		WARN(1, "Couldn't find context when removing PE\n");
	} else {
		mm_context_remove_copro(mm);
		mmdrop(mm);
	}
unlock:
	mutex_unlock(&spa->spa_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ocxl_spa_remove_pe);
