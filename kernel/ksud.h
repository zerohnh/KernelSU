#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <linux/types.h>
#include <linux/version.h>
#define KERNEL_VERSION_5_10 KERNEL_VERSION(5, 10, 0)

// Add Auto Add Symbol Export
#if LINUX_VERSION_CODE < KERNEL_VERSION_5_10 || defined(CONFIG_KSU_HOOK)
extern bool ksu_vfs_read_hook;
extern bool ksu_execveat_hook;
extern bool ksu_input_hook;
#endif

#define KSUD_PATH "/data/adb/ksud"

void ksu_on_post_fs_data(void);

bool ksu_is_safe_mode(void);

extern u32 ksu_devpts_sid;

#endif
