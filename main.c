/*
 * hf_usr_driver.c
 */
#include "hf-usr-protocol.h"
#include <hf/call.h>
#include <hf/ffa.h>
#include <hf/transport.h>
#include <hf/vm_ids.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
spinlock_t hf_send_lock;
struct page *hf_send_page;
struct page *hf_recv_page;
struct mailbox_buffers {
	void *send;
	void *recv;
};

static int expect_cnt = 0;

#define EXPECT_EQ(x, y)                                                \
	expect_cnt++;                                                  \
	if ((x) != (y)) {                                              \
		pr_info("[%d]error in: %s %s\n", expect_cnt, __FILE__, \
			__LINE__);                                     \
	}

#define EXPECT_NE(x, y)                                                \
	expect_cnt++;                                                  \
	if ((x) == (y)) {                                              \
		pr_info("[%d]error in: %s %s\n", expect_cnt, __FILE__, \
			__LINE__);                                     \
	}

struct hf_usr_driver_data {
	char *greeting;
	int number;
};
#define PROCFS_MAX_SIZE 1024
#define procfs_name "hf-usr-pipe"

/* TODO: need a lock to call ffa interfaces */

static ffa_vm_id_t current_vm_id;

static void log_ret(struct ffa_value ret)
{
	pr_info("ret func: %x, ret code: %d", ret.func, ret.arg2);
}

static uint64_t read_el(void)
{
	uint64_t __val;
	__asm__ volatile("mrs %0, currentEL" : "=r"(__val));
	return (__val >> 2) & 3;
}
static uint64_t read_NS(void)
{
	uint64_t __val;
	__val = (uint64_t)&__val;
	// __asm__ volatile("mrs %0, SP" : "=r" (__val));
	return ((__val) >> 63) & 1;
}

static inline struct ffa_value ffa_run_till_not_interrupt(
	ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx)
{
	struct ffa_value ret = ffa_run(vm_id, vcpu_idx);
	while (ret.func == FFA_INTERRUPT_32) {
		ret = ffa_run(vm_id, ffa_vcpu_index(ret));
	}
	return ret;
}

static void run_vm(void)
{
	struct ffa_value ret = ffa_run_till_not_interrupt(2, 0);
	if (ret.func != FFA_MSG_WAIT_32) {
		pr_alert("vm running err, func: %x, err: %d", ret.func,
			 ret.arg2);
	}
}

static void handle_input(void *input, size_t len)
{
	pr_info("read %u bit(s)", len);
	struct hf_usr_protocol *req = input;
	ffa_vm_id_t callee_id = req->vm_id;
	struct ffa_value ret = ffa_msg_send_direct_req(current_vm_id, callee_id,
						       23, 0, 0, 0, 0);
	if (ret.func == FFA_INTERRUPT_32) {
		ret = ffa_run_till_not_interrupt(callee_id,
						 ffa_vcpu_index(ret));
	}
	pr_info("vm %u ret with code: %x, %d", callee_id, ret.func, ret.arg2);
}

/* This function is called with the /proc file is written. */
static ssize_t procfile_write(struct file *file, const char __user *buff,
			      size_t len, loff_t *off)
{
	if (len != sizeof(struct hf_usr_protocol)) {
		return -EBADRQC;
	}
	void *input = kmalloc(len, GFP_KERNEL);
	if (!input) {
		return -ENOMEM;
	}

	if (copy_from_user(input, buff, len)) {
		kfree(input);
		return -EFAULT;
	}

	handle_input(input, len);

	off += len;
	kfree(input);

	return len;
}

static const struct proc_ops proc_file_fops = {
	//.proc_read = procfile_read,
	.proc_write = procfile_write,
};

static struct proc_dir_entry *hf_proc_file;

static int hf_usr_driver_probe(struct platform_device *dev)
{
	struct hf_usr_driver_data *pd =
		(struct hf_usr_driver_data *)(dev->dev.platform_data);

	pr_info("hf_usr_driver probe\n");
	pr_info("hf_usr_driver greeting: %s; %d\n", pd->greeting, pd->number);

	/* Your device initialization code */

	return 0;
}

static int hf_usr_driver_remove(struct platform_device *dev)
{
	pr_info("hf_usr_driver removed\n");

	/* Your device removal code */

	return 0;
}

static int hf_usr_driver_suspend(struct device *dev)
{
	pr_info("hf_usr_driver suspend\n");

	/* Your device suspend code */

	return 0;
}

static int hf_usr_driver_resume(struct device *dev)
{
	pr_info("hf_usr_driver resume\n");

	/* Your device resume code */

	return 0;
}

static const struct dev_pm_ops hf_usr_driver_pm_ops = {
	.suspend = hf_usr_driver_suspend,
	.resume = hf_usr_driver_resume,
	.poweroff = hf_usr_driver_suspend,
	.freeze = hf_usr_driver_suspend,
	.thaw = hf_usr_driver_resume,
	.restore = hf_usr_driver_resume,
};

static struct platform_driver hf_usr_driver = {
	.driver =
		{
			.name = "hf_usr_driver",
			.owner = THIS_MODULE,
			.pm = &hf_usr_driver_pm_ops,
		},
	.probe = hf_usr_driver_probe,
	.remove = hf_usr_driver_remove,
};
static struct ffa_memory_region mem_region;
static void share_mem(void)
{
	ffa_vm_id_t target_vm = 0x8002;
	int i;
	int8_t *not_aligned_shared_pages = kmalloc(PAGE_SIZE * 3, GFP_KERNEL);
	int8_t *shared_pages =
		((uint64_t)not_aligned_shared_pages + PAGE_SIZE - 1) /
		PAGE_SIZE * PAGE_SIZE;

	unsigned long flags;
	struct ffa_value ret;
	ffa_memory_handle_t handle;

	struct mailbox_buffers mb = {.send = page_address(hf_send_page),
				     .recv = page_address(hf_recv_page)};
	uint32_t total_length;
	uint32_t fragment_length;

	struct ffa_memory_region_constituent constituents[] = {
		{.address = virt_to_phys((uint64_t)shared_pages),
		 .page_count = 1},
		{.address = virt_to_phys((uint64_t)shared_pages + PAGE_SIZE),
		 .page_count = 1},
	};
	pr_info("%llx %llx %llx %llx\n", __pa((uint64_t)shared_pages),
		virt_to_phys((uint64_t)shared_pages), shared_pages,
		phys_to_virt(virt_to_phys((uint64_t)shared_pages)));

	/* Dirty the memory before sharing it. */
	memset(shared_pages, 'b', PAGE_SIZE * 2);

	spin_lock_irqsave(&hf_send_lock, flags);
	pr_info("recv id:%x\n",target_vm);

	EXPECT_EQ(ffa_memory_region_init_single_receiver(

			  &mem_region, HF_MAILBOX_SIZE, current_vm_id,
			  target_vm, constituents, ARRAY_SIZE(constituents), 0,
			  0, FFA_DATA_ACCESS_RW,
			  FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
			  FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
			  FFA_MEMORY_INNER_SHAREABLE, &total_length,
			  &fragment_length),
		  0);

	memcpy(mb.send, &mem_region, total_length);
	int access_count = mem_region.receiver_count;
	pr_info("tot: %d frag:%d page:%d", total_length, fragment_length,
		PAGE_SIZE);
	/* Send the first fragment without the last constituent. */
	fragment_length -= sizeof(struct ffa_memory_region_constituent);
	ret = ffa_mem_share(total_length, fragment_length);
	log_ret(ret);
	EXPECT_EQ(ret.func, FFA_MEM_FRAG_RX_32);
	EXPECT_EQ(ret.arg3, fragment_length);
	pr_info("a1:%x, a2:%x %x %x", ret.arg1, (uint32_t)(ret.arg2),
		ffa_frag_handle(ret), ffa_frag_handle(ret) >> 32);
	handle = ffa_frag_handle(ret);

	pr_info("Got handle %#llx.\n", handle);

	/* Send second fragment. */
	EXPECT_EQ(
		ffa_memory_fragment_init(mb.send, HF_MAILBOX_SIZE,
					 constituents + 1, 1, &fragment_length),
		0);
	ret = ffa_mem_frag_tx(handle, fragment_length);
	log_ret(ret);
	while (ret.arg2 == FFA_RETRY) {
		ret = ffa_mem_frag_tx(handle, fragment_length);
		log_ret(ret);
	}

	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
	EXPECT_EQ(ffa_mem_success_handle(ret), handle);
	pr_info("Got handle %#llx.\n", handle);
	EXPECT_NE(handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK,
		  FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR);
	spin_unlock_irqrestore(&hf_send_lock, flags);

	/* Make sure we can still write to it. */
	for (i = 0; i < PAGE_SIZE * 2; ++i) {
		shared_pages[i] = i;
	}
	pr_info("finish share mem to vm: %u", 2);

	pr_info("mem region size:%d %d\n", sizeof(struct ffa_memory_region),
		access_count * sizeof(struct ffa_memory_access));

	ffa_vm_id_t callee_id = target_vm;
	pr_info("share mem tot len:%d\n", total_length);

	memcpy(mb.send, &mem_region,
	       sizeof(struct ffa_memory_region) +
		       mem_region.receiver_count *
			       sizeof(struct ffa_memory_access));
	((struct ffa_memory_region *)mb.send)->handle = handle;
	ret = ffa_msg_send(current_vm_id, callee_id,
			   sizeof(struct ffa_memory_region), 0);
	log_ret(ret);
	ret = ffa_run_till_not_interrupt(callee_id, 0);
	log_ret(ret);
	/*if (ret.func == FFA_INTERRUPT_32) {
		ret = ffa_run_till_not_interrupt(callee_id,
						 ffa_vcpu_index(ret));
	}*/
	pr_info("vm %u ret with code: %x, %d", callee_id, ret.func, ret.arg2);
}

static int hf_usr_driver_init(void)
{
	struct ffa_value ffa_ret;
	int ret;

	pr_info("hf_usr_driver init\n");
	pr_info("el: %d ns:%d\n", read_el(), read_NS());

	current_vm_id = hf_vm_get_id();

	hf_proc_file = proc_create(procfs_name, 0222, NULL, &proc_file_fops);
	if (NULL == hf_proc_file) {
		proc_remove(hf_proc_file);
		pr_alert("Error:Could not initialize /proc/%s\n", procfs_name);
		return -ENOMEM;
	}

	pr_info("/proc/%s created\n", procfs_name);

	ret = platform_driver_register(&hf_usr_driver);

	if (ret) {
		pr_err("Unable to register driver\n");
		return ret;
	}

	/* Allocate a page for send and receive buffers. */
	hf_send_page = alloc_page(GFP_KERNEL);
	if (!hf_send_page) {
		pr_err("Unable to allocate send buffer\n");
		return -ENOMEM;
	}

	hf_recv_page = alloc_page(GFP_KERNEL);
	if (!hf_recv_page) {
		__free_page(hf_send_page);
		hf_send_page = NULL;
		pr_err("Unable to allocate receive buffer\n");
		return -ENOMEM;
	}
	ffa_ret = ffa_rxtx_map(page_to_phys(hf_send_page),
			       page_to_phys(hf_recv_page));
	if (ffa_ret.func != FFA_SUCCESS_32) {
		pr_err("Unable to configure VM mailbox.\n");
		log_ret(ffa_ret);
		ret = -EIO;
		__free_page(hf_recv_page);
		__free_page(hf_send_page);
		hf_recv_page = NULL;
		hf_send_page = NULL;
	}

	// run_vm();
	share_mem();
	pr_info("hf_usr_driver inited");
	return ret;
}

static void hf_usr_driver_exit(void)
{
	pr_info("hf_usr_driver exit\n");
	platform_driver_unregister(&hf_usr_driver);
	proc_remove(hf_proc_file);

	ffa_rx_release();
	ffa_rxtx_unmap();
	if (hf_send_page) {
		__free_page(hf_send_page);
		hf_send_page = NULL;
	}
	if (hf_recv_page) {
		__free_page(hf_recv_page);
		hf_recv_page = NULL;
	}
}

module_init(hf_usr_driver_init);
module_exit(hf_usr_driver_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Hafnium user level driver");