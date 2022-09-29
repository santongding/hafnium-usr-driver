/*
 * hf_usr_driver.c
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

struct hf_usr_driver_data {
	char *greeting;
	int number;
};
#define PROCFS_MAX_SIZE 1024
#define procfs_name "hf-usr-pipe"

static void handle_input(void *input, size_t len)
{
	pr_info("read %u bit(s)", len);
}

/* This function is called with the /proc file is written. */
static ssize_t procfile_write(struct file *file, const char __user *buff,
			      size_t len, loff_t *off)
{
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

static int hf_usr_driver_init(void)
{
	int ret;

	pr_info("hf_usr_driver init\n");

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

	return 0;
}

static void hf_usr_driver_exit(void)
{
	pr_info("hf_usr_driver exit\n");
	platform_driver_unregister(&hf_usr_driver);
	proc_remove(hf_proc_file);
}

module_init(hf_usr_driver_init);
module_exit(hf_usr_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Device Model example");