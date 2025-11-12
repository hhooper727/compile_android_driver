#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/random.h>
#include <linux/fs.h>           
#include <linux/uaccess.h>      
#include <linux/cdev.h>         
#include <linux/errno.h>  
#include "comm.h"
#include "memory.h"
#include "process.h"

// tfE98E2Q7pRZ2vsyZhseOhWK5oQsEr0D
static const unsigned char obf_key[] = {
    0x0e, 0x1c, 0x3f, 0x43, 0x42, 0x3f, 0x48, 0x2b,
    0x4d, 0x0a, 0x28, 0x20, 0x48, 0x0c, 0x09, 0x03,
    0x20, 0x12, 0x09, 0x1f, 0x35, 0x12, 0x2d, 0x31,
    0x4f, 0x15, 0x2b, 0x09, 0x3f, 0x08, 0x4a, 0x3e};
    
#define XOR_KEY_BYTE 0x7A
#define KEY_LEN 32

// 配套验证函数
static bool verify_auth_key(const char *user_key, size_t len)
{
    int i;
    if (len != KEY_LEN)
        return false;

    for (i = 0; i < KEY_LEN; i++)
    {
        if ((obf_key[i] ^ XOR_KEY_BYTE) != (unsigned char)user_key[i])
            return false;
    }
    return true;
}

static char dynamic_dev_name[32] = {0};

static void generate_random_name(char *buf, size_t buflen)
{
    int i;
    const char charset[] = "abcdefghijklmnopqrstuvwxyz"; // 26 letters
    unsigned char rand_data[8];
    if (!buf || buflen < 9)
    {
        return;
    }

    get_random_bytes(rand_data, sizeof(rand_data));

    for (i = 0; i < 8; i++)
    {
        buf[i] = charset[rand_data[i] % 26];
    }
    buf[8] = '\0';

    if (buflen > 9)
        memset(buf + 9, 0, buflen - 9);
}

int dispatch_open(struct inode *node, struct file *file)
{
    file->private_data = NULL; // NULL 表示未验证
    return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
    // 所有非 OP_INIT_KEY 操作必须已授权
    if (cmd != OP_INIT_KEY)
    {
        if (file->private_data == NULL)
        {
            return -EPERM; // 未认证
        }
    }

    switch (cmd)
    {
    case OP_INIT_KEY:
    {
        char user_key[0x100] = {0}; // 栈变量，非 static！

        if (copy_from_user(user_key, (void __user *)arg, sizeof(user_key) - 1))
        {
            return -EFAULT;
        }

        if (verify_auth_key(user_key, KEY_LEN))
        {
            file->private_data = (void *)1; // 当前 fd 授权
            return 0;
        }
        return -EPERM; // 密钥错误
    }

    case OP_READ_MEM:
    {
        COPY_MEMORY cm; // 栈变量
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
        {
            return -EFAULT;
        }
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
        {
            return -EINVAL;
        }
        break;
    }

    case OP_WRITE_MEM:
    {
        COPY_MEMORY cm; // 栈变量
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
        {
            return -EFAULT;
        }
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
        {
            return -EINVAL;
        }
        break;
    }

    case OP_MODULE_BASE:
    {
        MODULE_BASE mb;
        char name[0x100] = {0}; // 栈变量

        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
        {
            return -EFAULT;
        }
        if (copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1))
        {
            return -EFAULT;
        }

        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
        {
            return -EFAULT;
        }
        break;
    }

    default:
        return -ENOTTY;
    }

    return 0;
}
struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = dynamic_dev_name,
    .fops = &dispatch_functions,
};

int __init driver_entry(void)
{
    int ret;

    generate_random_name(dynamic_dev_name, sizeof(dynamic_dev_name));

    if (strlen(dynamic_dev_name) != 8)
    {
        printk(KERN_ERR "[-] Failed to generate valid device name, using fallback\n");
        strncpy(dynamic_dev_name, "rwdriver", sizeof(dynamic_dev_name) - 1);
        dynamic_dev_name[sizeof(dynamic_dev_name) - 1] = '\0';
    }

    printk(KERN_ERR "[+] Registering device: /dev/%s\n", dynamic_dev_name);

    ret = misc_register(&misc);
    if (ret)
    {
        printk(KERN_ERR "[-] misc_register failed: %d\n", ret);
        return ret;
    }

    printk(KERN_ERR "[+] Device registered successfully!\n");
    return 0;
}

void __exit driver_unload(void)
{
    printk(KERN_ERR "[+] driver_unload");
    misc_deregister(&misc);
}

asm(
    ".section .text\n"
    ".globl __cfi_jt_start\n"
    ".type __cfi_jt_start, %function\n"
    "__cfi_jt_start:\n"
    "ret\n"
    ".globl __cfi_jt_end\n"
    ".type __cfi_jt_end, %function\n"
    "__cfi_jt_end:\n"
    "ret\n"
);

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
