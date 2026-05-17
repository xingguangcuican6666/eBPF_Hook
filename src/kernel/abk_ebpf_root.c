#include <linux/abk_ebpf_root.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>

#define ABK_EBPF_ROOT_TAG "abk_ebpf_root"
#define ABK_EBPF_ROOT_MAX_GRANTS 32

static DEFINE_MUTEX(abk_grants_lock);
static struct abk_ebpf_root_grant abk_grants[ABK_EBPF_ROOT_MAX_GRANTS];
static unsigned int abk_grant_count;

static u64 abk_now_ms(void)
{
	return (u64)ktime_get_real_seconds() * 1000ULL;
}

static void abk_normalize_grant(struct abk_ebpf_root_grant *grant)
{
	grant->package_name[ABK_EBPF_ROOT_NAME_LEN - 1] = '\0';
	grant->cert_sha256[ABK_EBPF_ROOT_SHA256_HEX_LEN - 1] = '\0';
	grant->audit_tag[ABK_EBPF_ROOT_NAME_LEN - 1] = '\0';
}

static bool abk_grant_is_expired(const struct abk_ebpf_root_grant *grant)
{
	return grant->expires_at_ms != 0 && grant->expires_at_ms <= abk_now_ms();
}

static bool abk_grant_matches(const struct abk_ebpf_root_grant *grant, kuid_t uid,
			      const char *comm)
{
	if (grant->uid != __kuid_val(uid))
		return false;
	if (comm && grant->audit_tag[0] && strcmp(grant->audit_tag, comm))
		return false;
	if (abk_grant_is_expired(grant))
		return false;
	return true;
}

static void abk_prune_expired_locked(void)
{
	unsigned int i, dst = 0;

	for (i = 0; i < abk_grant_count; ++i) {
		if (abk_grant_is_expired(&abk_grants[i]))
			continue;
		if (dst != i)
			abk_grants[dst] = abk_grants[i];
		dst++;
	}

	if (dst < abk_grant_count)
		memset(&abk_grants[dst], 0,
		       (abk_grant_count - dst) * sizeof(abk_grants[0]));
	abk_grant_count = dst;
}

static void abk_fill_status(struct abk_ebpf_root_status *status)
{
	memset(status, 0, sizeof(*status));
	status->abi_version = ABK_EBPF_ROOT_STATUS_VERSION;
	status->flags = ABK_EBPF_ROOT_FLAG_AUDIT_ONLY |
			ABK_EBPF_ROOT_FLAG_DEVCTL_ONLY;
	status->max_grants = ABK_EBPF_ROOT_MAX_GRANTS;
	status->grant_count = abk_grant_count;
}

bool abk_bpf_is_granted(kuid_t uid, const char *comm)
{
	unsigned int i;
	bool allowed = false;

	mutex_lock(&abk_grants_lock);
	abk_prune_expired_locked();
	for (i = 0; i < abk_grant_count; ++i) {
		if (!abk_grant_matches(&abk_grants[i], uid, comm))
			continue;
		allowed = true;
		break;
	}
	mutex_unlock(&abk_grants_lock);
	return allowed;
}
EXPORT_SYMBOL_GPL(abk_bpf_is_granted);

static int abk_find_grant(const struct abk_ebpf_root_grant *grant)
{
	unsigned int i;

	for (i = 0; i < abk_grant_count; ++i) {
		if (abk_grants[i].uid == grant->uid &&
		    !strncmp(abk_grants[i].package_name, grant->package_name,
			     sizeof(grant->package_name)) &&
		    !strncmp(abk_grants[i].cert_sha256, grant->cert_sha256,
			     sizeof(grant->cert_sha256))) {
			return i;
		}
	}
	return -ENOENT;
}

static long abk_ebpf_root_ioctl_locked(unsigned int cmd, unsigned long arg)
{
	struct abk_ebpf_root_grant grant;
	struct abk_ebpf_root_grant_list list;
	struct abk_ebpf_root_status status;
	int index;

	abk_prune_expired_locked();

	switch (cmd) {
	case ABK_EBPF_ROOT_IOC_ADD_GRANT:
		if (copy_from_user(&grant, (void __user *)arg, sizeof(grant)))
			return -EFAULT;
		abk_normalize_grant(&grant);
		if (grant.uid < 0 || !grant.package_name[0] || !grant.cert_sha256[0])
			return -EINVAL;
		index = abk_find_grant(&grant);
		if (index >= 0) {
			abk_grants[index] = grant;
			return 0;
		}
		if (abk_grant_count >= ABK_EBPF_ROOT_MAX_GRANTS)
			return -ENOSPC;
		abk_grants[abk_grant_count++] = grant;
		return 0;
	case ABK_EBPF_ROOT_IOC_DEL_GRANT:
		if (copy_from_user(&grant, (void __user *)arg, sizeof(grant)))
			return -EFAULT;
		index = abk_find_grant(&grant);
		if (index < 0)
			return index;
		memmove(&abk_grants[index], &abk_grants[index + 1],
			(abk_grant_count - index - 1) * sizeof(abk_grants[0]));
		memset(&abk_grants[abk_grant_count - 1], 0, sizeof(abk_grants[0]));
		abk_grant_count--;
		return 0;
	case ABK_EBPF_ROOT_IOC_LIST_GRANTS:
		memset(&list, 0, sizeof(list));
		list.count = abk_grant_count;
		memcpy(list.grants, abk_grants, sizeof(abk_grants));
		if (copy_to_user((void __user *)arg, &list, sizeof(list)))
			return -EFAULT;
		return 0;
	case ABK_EBPF_ROOT_IOC_FLUSH_EXPIRED:
		abk_prune_expired_locked();
		return 0;
	case ABK_EBPF_ROOT_IOC_GET_STATUS:
		abk_fill_status(&status);
		if (copy_to_user((void __user *)arg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

long abk_ebpf_root_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	mutex_lock(&abk_grants_lock);
	ret = abk_ebpf_root_ioctl_locked(cmd, arg);
	mutex_unlock(&abk_grants_lock);
	return ret;
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

	pr_info("%s: audit-only control plane registered\n", ABK_EBPF_ROOT_TAG);
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
MODULE_DESCRIPTION("ABK eBPF audit-only /dev control plane");
