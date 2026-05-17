#include <linux/abk_ebpf_root.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define ABK_EBPF_ROOT_TAG "abk_ebpf_root"
#define ABK_EBPF_ROOT_MAX_GRANTS 32

static void abk_fill_status(struct abk_ebpf_root_status *status)
{
	memset(status, 0, sizeof(*status));
	status->abi_version = ABK_EBPF_ROOT_STATUS_VERSION;
	status->flags = ABK_EBPF_ROOT_FLAG_AUDIT_ONLY |
			ABK_EBPF_ROOT_FLAG_DEVCTL_ONLY;
	status->max_grants = ABK_EBPF_ROOT_MAX_GRANTS;
	status->grant_count = 0;
}

bool abk_bpf_is_granted(kuid_t uid, const char *comm)
{
	return false;
}
EXPORT_SYMBOL_GPL(abk_bpf_is_granted);

long abk_ebpf_root_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct abk_ebpf_root_status status;

	switch (cmd) {
	case ABK_EBPF_ROOT_IOC_GET_STATUS:
		abk_fill_status(&status);
		if (copy_to_user((void __user *)arg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	case ABK_EBPF_ROOT_IOC_ADD_GRANT:
	case ABK_EBPF_ROOT_IOC_DEL_GRANT:
	case ABK_EBPF_ROOT_IOC_LIST_GRANTS:
	case ABK_EBPF_ROOT_IOC_FLUSH_EXPIRED:
		return -EOPNOTSUPP;
	default:
		return -ENOTTY;
	}
}
EXPORT_SYMBOL_GPL(abk_ebpf_root_ioctl);

static long abk_misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return abk_ebpf_root_ioctl(file, cmd, arg);
}

static const struct file_operations abk_rootctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = abk_misc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = abk_misc_ioctl,
#endif
};

static struct miscdevice abk_rootctl_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "abk_ebpf_rootctl",
	.fops = &abk_rootctl_fops,
	.mode = 0600,
};

static int __init abk_ebpf_root_init(void)
{
	int ret;

	ret = misc_register(&abk_rootctl_misc);
	if (ret)
		return ret;

	pr_info("%s: minimal control plane registered\n", ABK_EBPF_ROOT_TAG);
	return 0;
}

static void __exit abk_ebpf_root_exit(void)
{
	misc_deregister(&abk_rootctl_misc);
}

module_init(abk_ebpf_root_init);
module_exit(abk_ebpf_root_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Codex");
MODULE_DESCRIPTION("ABK eBPF minimal /dev control plane");
