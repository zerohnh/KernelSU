(
sed -i '/INIT_WORK(&stop_input_hook_work, do_stop_input_hook);/a\\n#endif' ./kernel/ksud.c
)

(
sed -i '/void ksu_ksud_exit()/,/}/c\
void ksu_ksud_exit()\
{\
#ifdef CONFIG_KPROBES\
	unregister_kprobe(&execve_kp);\
	unregister_kprobe(&vfs_read_kp);\
	unregister_kprobe(&input_event_kp);\
\
	flush_scheduled_work();\
#endif\
}' ./kernel/ksud.c
)
