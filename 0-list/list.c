// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Sundi Guan <913887524@qq.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct list_info {
	char name[24];
	int length;
	struct list_head list;
};

static DEFINE_RWLOCK(lock);
static struct list_head head;

static struct list_info *alloc_list_info(char *name)
{
	struct list_info *info;
	int length;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return NULL;
	memset(info->name, 0, sizeof(info->name));
	strncpy(info->name, name, sizeof(info->name) - 1);
	length = sizeof(info->name);
	while (!info->name[length - 1])
		length--;
	info->length = length;
	return info;
}

static int add_name_front(char *name)
{
	struct list_info *info;

	info = alloc_list_info(name);
	if (info == NULL)
		return -ENOMEM;

	write_lock(&lock);

	list_add(&info->list, &head);

	write_unlock(&lock);
	return 0;
}

static int add_name_tail(char *name)
{
	struct list_info *info;

	info = alloc_list_info(name);
	if (info == NULL)
		return -ENOMEM;

	write_lock(&lock);

	list_add_tail(&info->list, &head);

	write_unlock(&lock);
	return 0;
}

static int delete_first_name(char *name)
{
	struct list_info *p, *q;

	write_lock(&lock);

	list_for_each_entry_safe(p, q, &head, list) {
		if (strcmp(p->name, name) == 0) {
			list_del(&p->list);
			kfree(p);
			goto free;
		}
	}

free:
	write_unlock(&lock);
	return 0;
}

static int delete_all_name(char *name)
{
	struct list_info *p, *q;

	write_lock(&lock);

	list_for_each_entry_safe(p, q, &head, list) {
		if (strcmp(p->name, name) == 0) {
			list_del(&p->list);
			kfree(p);
		}
	}

	write_unlock(&lock);
	return 0;
}

static int delete_all(void)
{
	struct list_info *p, *q;

	write_lock(&lock);

	list_for_each_entry_safe(p, q, &head, list) {
		kfree(p);
	}

	write_unlock(&lock);
	return 0;
}

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_info *p;

	read_lock(&lock);

	list_for_each_entry(p, &head, list) {
		seq_write(m, p->name, p->length);
	}

	read_unlock(&lock);

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;
	char *buffer_p;
	char *comm, *name;
	int ret;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 */
	buffer_p = local_buffer;
	comm = strsep(&buffer_p, " ");
	if (comm == NULL)
		return -EINVAL;
	name = strsep(&buffer_p, " ");
	if (name == NULL || name[0] == '\0')
		return -EINVAL;
	if (strcmp(comm, "addf") == 0)
		ret = add_name_front(name);
	else if (strcmp(comm, "adde") == 0)
		ret = add_name_tail(name);
	else if (strcmp(comm, "delf") == 0)
		ret = delete_first_name(name);
	else if (strcmp(comm, "dela") == 0)
		ret = delete_all_name(name);
	else
		ret = -EINVAL;
	if (ret)
		return ret;
	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	INIT_LIST_HEAD(&head);
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	delete_all();
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Sundi Guan <913887524@qq.com>");
MODULE_LICENSE("GPL v2");
