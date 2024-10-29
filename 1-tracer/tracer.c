// SPDX-License-Identifier: GPL-2.0+
/*
 * tracer.c - Linux kprobe tracer
 * Gather all code parts in a file make things in a mess...
 * Next assignment I should take them apart.
 *
 * Author: Sundi Guan <913887524@qq.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>

#include "tracer.h"

#define BUF_SIZE 32

static struct proc_dir_entry *tracer_proc;

struct malloc_info {
	size_t addr;
	size_t size;
};

struct proc_info {
	struct hlist_node node;
	struct rcu_head rcu;
	// Can only store up to BUF_SIZE malloc infomation,
	// kmalloc in probe program may be in deadlock (monitoring it).
	// My friends told me kprobe will disable probe in probe program.
	// I have not try it before (and do not know why),
	// choose a direct implement.
	struct malloc_info used[BUF_SIZE], pending;
	pid_t pid;
	int kmalloc, kfree;
	int kmalloc_mem, kfree_mem;
	// these vars don't need to be atomic,
	// every thread will access its own proc_info.
	// A bad implement...
	atomic_t sched;
	atomic_t up, down;
	atomic_t lock, unlock;
};

struct dev_data {
	spinlock_t lock;
	struct hlist_head ht[256];
};

static struct dev_data dev;

static int tracer_proc_show(struct seq_file *m, void *v)
{
	int bkt;
	struct proc_info *cur;
	const char *guiding_str =
		"PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock\n";

	rcu_read_lock();

	// Output first guiding line to pass test
	seq_puts(m, guiding_str);
	hash_for_each_rcu(dev.ht, bkt, cur, node) {
		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n",
			cur->pid, cur->kmalloc, cur->kfree,
			cur->kmalloc_mem, cur->kfree_mem,
			atomic_read(&cur->sched), atomic_read(&cur->up),
			atomic_read(&cur->down),
			atomic_read(&cur->lock), atomic_read(&cur->unlock));
	}

	rcu_read_unlock();
	return 0;
}

static int tracer_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

static long tracer_dev_add_one(pid_t pid)
{
	struct proc_info *info;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;
	memset(info, 0, sizeof(*info));
	info->pid = pid;

	spin_lock(&dev.lock);

	hash_add_rcu(dev.ht, &info->node, pid);

	spin_unlock(&dev.lock);
	return 0;
}

static void tracer_free_node(struct rcu_head *rc)
{
	struct proc_info *cur;

	cur = container_of(rc, struct proc_info, rcu);
	kfree(cur);
}

static long tracer_dev_del_one(pid_t pid)
{
	bool finded;
	struct proc_info *cur;
	struct hlist_node *tmp;

	spin_lock(&dev.lock);

	finded = false;
	hash_for_each_possible_safe(dev.ht, cur, tmp, node, pid) {
		if (cur->pid != pid)
			continue;
		finded = true;
		hlist_del_rcu(&cur->node);
		call_rcu(&cur->rcu, tracer_free_node);
	}

	spin_unlock(&dev.lock);

	return finded ? 0 : -EINVAL;
}

static inline struct proc_info *tracer_dev_find(pid_t pid)
{
	struct proc_info *cur;

	hash_for_each_possible_rcu(dev.ht, cur, node, pid)
		if (cur->pid == pid)
			return cur;
	return NULL;
}

static long tracer_dev_ioctl(
	struct file *file,
	unsigned int cmd,
	unsigned long arg
)
{
	long ret = 0;
	pid_t pid;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pid = arg;
		ret = tracer_dev_add_one(pid);
		break;
	case TRACER_REMOVE_PROCESS:
		pid = arg;
		ret = tracer_dev_del_one(pid);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static const struct proc_ops p_ops = {
	.proc_open	= tracer_proc_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};

static const struct file_operations d_ops = {
	.open		= nonseekable_open,
	.release	= NULL,
	.unlocked_ioctl = tracer_dev_ioctl,
};

static struct miscdevice d_misc_dev = {
	.minor		= TRACER_DEV_MINOR,
	.name		= TRACER_DEV_NAME,
	.fops		= &d_ops,
};


// This handler may violate linux lockdeps...
// I have no better idea to skip this, because it's not my fault.
static int kmalloc_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	struct proc_info *info;

	// eax -> size
	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info) {
		info->kmalloc++;
		info->kmalloc_mem += regs->ax;
		info->pending.size = regs->ax;
	}

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(kmalloc_entry_handler);

static int kmalloc_ret_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	bool finded;
	int i;
	struct proc_info *info;

	// eax -> size
	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info) {
		finded = false;
		info->pending.addr = regs->ax;
		for (i = 0 ; i < BUF_SIZE ; i++) {
			if (info->used[i].addr)
				continue;
			info->used[i] = info->pending;
			finded = true;
			break;
		}
		if (!finded)
			pr_info("encoutner oom!\n");
	}

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(kmalloc_ret_handler);

static struct kretprobe kmalloc_probe = {
	.entry_handler	= kmalloc_entry_handler,
	.handler = kmalloc_ret_handler,
	.maxactive = 32,
	.kp.symbol_name = "__kmalloc",
};

static int kfree_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	bool finded;
	int i;
	struct proc_info *info;
	// eax -> addr
	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info) {
		finded = false;
		info->kfree++;
		for (i = 0 ; i < BUF_SIZE ; i++) {
			if (info->used[i].addr != regs->ax)
				continue;
			info->kfree_mem += info->used[i].size;
			info->used[i].addr = 0;
			finded = true;
		}
	}

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(kfree_entry_handler);

static struct kretprobe kfree_probe = {
	.entry_handler	= kfree_entry_handler,
	.maxactive = 32,
	.kp.symbol_name = "kfree",
};

// So many dirty works, maybe a macro can help me.
static int schedule_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	struct proc_info *info;

	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info)
		atomic_inc(&info->sched);

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(schedule_entry_handler);

static struct kretprobe schedule_probe = {
	.entry_handler = schedule_entry_handler,
	// Enlarge concurrent threads to pass stress test
	.maxactive = 64,
	.kp.symbol_name = "schedule",
};

static int up_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	struct proc_info *info;

	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info)
		atomic_inc(&info->up);

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(up_entry_handler);

static struct kretprobe up_probe = {
	.entry_handler = up_entry_handler,
	.maxactive = 32,
	.kp.symbol_name = "up",
};

static int down_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	struct proc_info *info;

	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info)
		atomic_inc(&info->down);

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(down_entry_handler);

static struct kretprobe down_probe = {
	.entry_handler = down_entry_handler,
	.maxactive = 32,
	.kp.symbol_name = "down_interruptible",
};

static int lock_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	struct proc_info *info;

	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info)
		atomic_inc(&info->lock);

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(lock_entry_handler);

static struct kretprobe lock_probe = {
	.entry_handler = lock_entry_handler,
	.maxactive = 32,
	.kp.symbol_name = "mutex_lock_nested",
};

static int unlock_entry_handler(
	struct kretprobe_instance *ri,
	struct pt_regs *regs
)
{
	struct proc_info *info;

	rcu_read_lock();

	info = tracer_dev_find(current->pid);
	if (info)
		atomic_inc(&info->unlock);

	rcu_read_unlock();
	return 0;
}
NOKPROBE_SYMBOL(unlock_entry_handler);

static struct kretprobe unlock_probe = {
	.entry_handler = unlock_entry_handler,
	.maxactive = 32,
	.kp.symbol_name = "mutex_unlock",
};

static struct kretprobe *kprobes[7] = {
	&kmalloc_probe,
	&kfree_probe,
	&schedule_probe,
	&up_probe,
	&down_probe,
	&lock_probe,
	&unlock_probe,
};

static int __init tracer_init(void)
{
	int err = 0;
	// create proc file
	tracer_proc = proc_create(TRACER_DEV_NAME, 0000, NULL, &p_ops);
	if (!tracer_proc) {
		err = -ENOMEM;
		pr_info("oom!\n");
		goto cleanup;
	}
	// create device file
	err = misc_register(&d_misc_dev);
	if (err) {
		pr_info("misc error!\n");
		goto proc_cleanup;
	}
	// init lock
	spin_lock_init(&dev.lock);
	// init hash table
	hash_init(dev.ht);
	// register handler
	err = register_kretprobes(kprobes, 7);
	if (err) {
		pr_info("register error!\n");
		goto dev_cleanup;
	}
	return err;
dev_cleanup:
	misc_deregister(&d_misc_dev);
proc_cleanup:
	proc_remove(tracer_proc);
cleanup:
	return err;
}

static void __exit tracer_exit(void)
{
	int bkt;
	struct proc_info *cur;
	struct hlist_node *tmp;
	// remove proc
	proc_remove(tracer_proc);
	// remove cdev
	misc_deregister(&d_misc_dev);
	// free hlist
	hash_for_each_safe(dev.ht, bkt, tmp, cur, node) {
		hlist_del(&cur->node);
		kfree(cur);
	}
	// unregister handler
	unregister_kretprobes(kprobes, 7);
}

module_init(tracer_init);
module_exit(tracer_exit);
MODULE_DESCRIPTION("Linux kprobe tracer");
MODULE_AUTHOR("Sundi Guan <913887524@qq.com>");
MODULE_LICENSE("GPL v2");
