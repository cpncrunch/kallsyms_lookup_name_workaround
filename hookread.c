#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>


unsigned long **SYS_CALL_TABLE;

#define readMe() write_cr0(read_cr0() & (~0x10000))
#define protectMe() write_cr0(read_cr0() | 0x10000)

static struct kprobe kp = {
    .symbol_name = "sys_call_table"
};

asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int rk_write(unsigned int fd, const char __user* buf, size_t count){
	return (*original_write)(fd, buf, count);
}

asmlinkage int (*original_read)(unsigned int, void __user*, size_t);
asmlinkage int rk_read(unsigned int fd, void __user* buf, size_t count){
	return (*original_read)(fd, buf, count);
}
static int __init rk_init(void){

	//SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table");
	register_kprobe(&kp);
	
	printk(KERN_INFO "Hello.\n");
	printk(KERN_INFO "System call table at %p\n", kp.addr);
	
	readMe();
	original_write = (void*)SYS_CALL_TABLE[__NR_write];
	SYS_CALL_TABLE[__NR_write] = (unsigned long*)rk_write;
	
	original_read = (void*)SYS_CALL_TABLE[__NR_read];
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)rk_read;
	protectMe();
	
	return 0;
}
static void __exit rk_exit(void){
	readMe();
	SYS_CALL_TABLE[__NR_write] = (unsigned long*)original_write;
	SYS_CALL_TABLE[__NR_read] = (unsigned long*)original_read;
	protectMe();
	unregister_kprobe(&kp);
	printk(KERN_INFO "Goodbye.");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("me");
MODULE_DESCRIPTION("Hooking");
MODULE_VERSION("0");
module_init(rk_init);
module_exit(rk_exit);
