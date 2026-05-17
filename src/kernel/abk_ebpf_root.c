#include <linux/abk_ebpf_root.h>

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define ABK_EBPF_ROOT_TAG "abk_ebpf_root"
#define ABK_EBPF_ROOT_MAX_GRANTS 32

static char abk_manager_package[ABK_EBPF_ROOT_NAME_LEN] = "com.abk.kernel";
static char abk_manager_cert_sha256[ABK_EBPF_ROOT_SHA256_HEX_LEN] =
	"34e5e843952277759603cd0f949770b24c868530d80d7baeff08776a7e132b16";
static unsigned int abk_manager_cert_size = 1407U;

module_param_string(manager_package, abk_manager_package,
		    sizeof(abk_manager_package), 0400);
MODULE_PARM_DESC(manager_package, "Trusted manager package");
module_param_string(manager_cert_sha256, abk_manager_cert_sha256,
		    sizeof(abk_manager_cert_sha256), 0400);
MODULE_PARM_DESC(manager_cert_sha256, "Trusted manager signing cert sha256");
module_param_named(manager_cert_size, abk_manager_cert_size, uint, 0400);
MODULE_PARM_DESC(manager_cert_size, "Trusted manager signing cert size");

static DEFINE_MUTEX(abk_grants_lock);
static struct abk_ebpf_root_grant abk_grants[ABK_EBPF_ROOT_MAX_GRANTS];
static unsigned int abk_grant_count;

bool abk_bpf_is_granted(kuid_t uid, const char *comm)
{
	unsigned int i;
	bool allowed = false;

	mutex_lock(&abk_grants_lock);
	for (i = 0; i < abk_grant_count; ++i) {
		if (abk_grants[i].uid != __kuid_val(uid))
			continue;
		if (comm && abk_grants[i].audit_tag[0] &&
		    strcmp(abk_grants[i].audit_tag, comm))
			continue;
		allowed = true;
		if (abk_grants[i].one_shot) {
			memmove(&abk_grants[i], &abk_grants[i + 1],
				(abk_grant_count - i - 1) * sizeof(abk_grants[0]));
			memset(&abk_grants[abk_grant_count - 1], 0,
			       sizeof(abk_grants[0]));
			abk_grant_count--;
		}
		break;
	}
	mutex_unlock(&abk_grants_lock);
	return allowed;
}
EXPORT_SYMBOL_GPL(abk_bpf_is_granted);

static int abk_set_root_caps(struct cred *new)
{
	kuid_t root_uid = GLOBAL_ROOT_UID;
	kgid_t root_gid = GLOBAL_ROOT_GID;

	new->uid = root_uid;
	new->gid = root_gid;
	new->euid = root_uid;
	new->egid = root_gid;
	new->suid = root_uid;
	new->sgid = root_gid;
	new->fsuid = root_uid;
	new->fsgid = root_gid;
	cap_raise(new->cap_effective, CAP_SYS_ADMIN);
	cap_raise(new->cap_permitted, CAP_SYS_ADMIN);
	cap_raise(new->cap_effective, CAP_SETUID);
	cap_raise(new->cap_permitted, CAP_SETUID);
	cap_raise(new->cap_effective, CAP_SETGID);
	cap_raise(new->cap_permitted, CAP_SETGID);
	cap_raise(new->cap_bset, CAP_SYS_ADMIN);
	cap_raise(new->cap_bset, CAP_SETUID);
	cap_raise(new->cap_bset, CAP_SETGID);
	return 0;
}

int abk_bpf_escalate_current(__u32 profile_id)
{
	struct cred *new;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	switch (profile_id) {
	case ABK_EBPF_ROOT_PROFILE_SHELL:
		abk_set_root_caps(new);
		break;
	case ABK_EBPF_ROOT_PROFILE_CAPS_ONLY:
		cap_raise(new->cap_effective, CAP_SYS_ADMIN);
		cap_raise(new->cap_permitted, CAP_SYS_ADMIN);
		break;
	default:
		abort_creds(new);
		return -EINVAL;
	}

	return commit_creds(new);
}
EXPORT_SYMBOL_GPL(abk_bpf_escalate_current);

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
	int index;

	switch (cmd) {
	case ABK_EBPF_ROOT_IOC_ADD_GRANT:
		if (copy_from_user(&grant, (void __user *)arg, sizeof(grant)))
			return -EFAULT;
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
		memset(abk_grants, 0, sizeof(abk_grants));
		abk_grant_count = 0;
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

	pr_info("%s: enabled for manager=%s cert_size=%u cert_sha256=%s\n",
		ABK_EBPF_ROOT_TAG, abk_manager_package, abk_manager_cert_size,
		abk_manager_cert_sha256);
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
MODULE_DESCRIPTION("ABK eBPF-assisted root PoC control plane");
