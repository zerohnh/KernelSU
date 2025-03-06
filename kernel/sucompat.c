#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"


extern void ksu_escape_to_root();

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    static const char sh_path[] = SH_PATH;
    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	const char su[] = SU_PATH;

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		pr_info("faccessat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS_SUS_SU)
struct filename* susfs_ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags) {
    const char su[] = SU_PATH;
    struct filename *name = getname_flags(*filename_user, getname_statx_lookup_flags(*flags), NULL);

    if (unlikely(IS_ERR(name) || name->name == NULL)) {
        return name;
    }

    if (!ksu_is_allow_uid(current_uid().val)) {
        return name;
    }

    if (likely(memcmp(name->name, su, sizeof(su)))) {
        return name;
    }

    const char sh[] = SH_PATH;
    pr_info("vfs_fstatat su->sh!\n");
    memcpy((void *)name->name, sh, sizeof(sh));
    return name;
}
#endif

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	// const char sh[] = SH_PATH;
	const char su[] = SU_PATH;

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	if (unlikely(!filename_user)) {
		return 0;
	}

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *__never_use_argv, void *__never_use_envp, int *__never_use_flags)
{
    const char su[] = SU_PATH;
    const char ksud[] = KSUD_PATH;

    if (unlikely(!filename_ptr))
        return 0;

    struct filename *filename = *filename_ptr;
    if (IS_ERR(filename)) {
        return 0;
    }

    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;

    if (!ksu_is_allow_uid(current_uid().val))
        return 0;

    pr_info("do_execveat_common su found\n");
    memcpy((void *)filename->name, ksud, sizeof(ksud));

    ksu_escape_to_root();

    return 0;
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user, void *__never_use_argv, void *__never_use_envp, int *__never_use_flags)
{
    const char su[] = SU_PATH;

    if (unlikely(!filename_user))
        return 0;

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (likely(memcmp(path, su, sizeof(su))))
        return 0;

    if (!ksu_is_allow_uid(current_uid().val))
        return 0;

    pr_info("sys_execve su found\n");
    *filename_user = ksud_user_path();

    ksu_escape_to_root();

    return 0;
}

int ksu_handle_devpts(struct inode *inode)
{
    if (!current->mm) {
        return 0;
    }

    uid_t uid = current_uid().val;
    if (uid % 100000 < 10000) {
        return 0;
    }

    if (!ksu_is_allow_uid(uid))
        return 0;

    if (ksu_devpts_sid) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
        struct inode_security_struct *sec = selinux_inode(inode);
#else
        struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif
        if (sec) {
            sec->sid = ksu_devpts_sid;
        }
    }

    return 0;
}

#ifdef CONFIG_KPROBES
static int faccessat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int *dfd = (int *)&PT_REGS_PARM1(regs);
    const char __user **filename_user = (const char __user **)&PT_REGS_PARM2(regs);
    int *mode = (int *)&PT_REGS_PARM3(regs);

    return ksu_handle_faccessat(dfd, filename_user, mode, NULL);
}

static int newfstatat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int *dfd = (int *)&PT_REGS_PARM1(regs);
    const char __user **filename_user = (const char __user **)&PT_REGS_PARM2(regs);
    int *flags = (int *)&PT_REGS_PARM3(regs);

    return ksu_handle_stat(dfd, filename_user, flags);
}

static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    int *fd = (int *)&PT_REGS_PARM1(regs);
    struct filename **filename_ptr = (struct filename **)&PT_REGS_PARM2(regs);

    return ksu_handle_execveat_sucompat(fd, filename_ptr, NULL, NULL, NULL);
}

static int pts_unix98_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct inode *inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
    struct file *file = (struct file *)PT_REGS_PARM2(regs);
    inode = file->f_path.dentry->d_inode;
#else
    inode = (struct inode *)PT_REGS_PARM2(regs);
#endif
    return ksu_handle_devpts(inode);
}

static struct kprobe faccessat_kp = {
    .symbol_name = "faccessat",
    .pre_handler = faccessat_handler_pre,
};

static struct kprobe newfstatat_kp = {
    .symbol_name = "newfstatat",
    .pre_handler = newfstatat_handler_pre,
};

static struct kprobe execve_kp = {
    .symbol_name = "sys_execve",
    .pre_handler = execve_handler_pre,
};

static struct kprobe pts_unix98_lookup_kp = {
    .symbol_name = "pts_unix98_lookup",
    .pre_handler = pts_unix98_lookup_pre,
};
// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
    int ret;
    ret = register_kprobe(&execve_kp);
    pr_info("sucompat: execve_kp: %d\n", ret);
    ret = register_kprobe(&newfstatat_kp);
    pr_info("sucompat: newfstatat_kp: %d\n", ret);
    ret = register_kprobe(&faccessat_kp);
    pr_info("sucompat: faccessat_kp: %d\n", ret);
    ret = register_kprobe(&pts_unix98_lookup_kp);
    pr_info("sucompat: devpts_kp: %d\n", ret);
}

void ksu_sucompat_exit()
{
    unregister_kprobe(&execve_kp);
    unregister_kprobe(&newfstatat_kp);
    unregister_kprobe(&faccessat_kp);
    unregister_kprobe(&pts_unix98_lookup_kp);
}

#endif // CONFIG_KPROBES

#ifdef CONFIG_KSU_SUSFS_SUS_SU
extern bool ksu_devpts_hook;

void ksu_susfs_disable_sus_su(void) {
    enable_kprobe(&execve_kp);
    enable_kprobe(&newfstatat_kp);
    enable_kprobe(&faccessat_kp);
    enable_kprobe(&pts_unix98_lookup_kp);
    ksu_devpts_hook = false;
}

void ksu_susfs_enable_sus_su(void) {
    disable_kprobe(&execve_kp);
    disable_kprobe(&newfstatat_kp);
    disable_kprobe(&faccessat_kp);
    disable_kprobe(&pts_unix98_lookup_kp);
    ksu_devpts_hook = true;
}
#endif // CONFIG_KSU_SUSFS_SUS_SU
