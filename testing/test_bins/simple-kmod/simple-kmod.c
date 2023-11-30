#include <linux/module.h>  // Needed for all modules
#include <linux/kernel.h>  // Needed for KERN_INFO

MODULE_LICENSE("GPL"); // License type -- this affects available functionality
MODULE_AUTHOR("Foo Bar"); // The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Hello World Kernel Module"); // The description -- see modinfo
MODULE_VERSION("0.1"); // The version of the module

static int __init hello_start(void)
{
    printk(KERN_INFO "Hello, world!\n");
    return 0; // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_end(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(hello_start);
module_exit(hello_end);
