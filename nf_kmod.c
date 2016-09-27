//'Hello World' kernel module, logs call to init_module
// and cleanup_module to /var/log/messages

#define __KERNEL__
#define MODULE

#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void)
{
   printk(KERN_ERR "Bryan init_module() called\n");
   return 0;
}

void cleanup_module(void)
{
   printk(KERN_ERR "Bryan cleanup_module() called\n");
}

