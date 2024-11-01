// SPDX-License-Identifier: GPL-2.0+
/*
 * uart16550.c - Linux uart16550 driver
 *
 * Author: Sundi Guan <913887524@qq.com>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/fs.h>

#include "uart16550.h"

#define MODULE_NAME	"uart16550"
#define BUF_SIZE	32
#define KFIFO_SIZE	64

#define COM1_PORT	0x3f8
#define COM1_INTR	4

#define COM2_PORT	0x2f8
#define COM2_INTR	3

#define UART_READ			0
#define UART_WRITE			0
#define UART_INTR_ENABLE		1
#define UART_BAUD_LOW			0
#define UART_BAUD_HIGH			1
#define UART_INTR_IDENTIFICATION	2
#define UART_FIFO_CONTROL		2
#define UART_LINE_CONTROL		3
#define UART_MODEM_CONTROL		4
#define UART_LINE_STATUS		5
#define UART_MODEM_STATUS		6

#define INTR_PENDING		0x01
#define INTR_LEVEL		0x02
#define INTR_TIMEOUT		0x04

#define INTR_MODEM_STATUS		0x0
#define INTR_REGISTER_EMPTY		0x1
#define INTR_DATA_AVAILABLE		0x2
#define INTR_RECIEVE_LINE_STATUS	0x3

#define LINE_DATA_READY		0x01
#define LINE_OVERRUN		0x02
#define LINE_PARITY_ERROR	0x04
#define LINE_FRAMING_ERROR	0x08
#define LINE_BREAK		0x10
#define LINE_REGISTER_EMPTY	0x20
#define LINE_TRASMITTER_EMPTY	0x40
#define LINE_IMPENDING_ERROR	0x80

static int major = 42;
static int option = OPTION_BOTH;
module_param(major, int, 0);
module_param(option, int, 0);

struct serial_info {
	struct cdev cdev;
	int ioport_base;
	spinlock_t lock;
	struct mutex read, write;
	wait_queue_head_t wq_in, wq_out;
	atomic_t enabled;
	// serial in
	DECLARE_KFIFO(sin, char, KFIFO_SIZE);
	// serial out
	DECLARE_KFIFO(sout, char, KFIFO_SIZE);
};
// 0 -> COM1
// 1 -> COM2
struct serial_info serial[2];

static int
serial_setup(struct serial_info *serial,
	struct uart16550_line_info *line)
{
	unsigned long flags;
	int ioport_base;
	u8 line_ctl, fifo_ctl, intr_enable;

	spin_lock_irqsave(&serial->lock, flags);

	if (atomic_read(&serial->enabled))
		return -EBUSY;

	ioport_base = serial->ioport_base;
	// disable intr
	outb(0x00, ioport_base + UART_INTR_ENABLE);
	// enable DLAB
	outb(0x80, ioport_base + UART_LINE_CONTROL);
	outb(0x00, ioport_base + UART_BAUD_HIGH);
	outb(line->baud, ioport_base + UART_BAUD_LOW);
	// setup line control
	line_ctl = line->len | line->stop | line->par;
	outb(line_ctl, ioport_base + UART_LINE_CONTROL);
	// enable fifo
	fifo_ctl = 0xc7; // 14bytes fifo
	outb(fifo_ctl, ioport_base + UART_FIFO_CONTROL);
	// enable interrupt
	intr_enable = 0x07; // skip modem status
	outb(intr_enable, ioport_base + UART_INTR_ENABLE);
	// enable modem
	outb(0xf, ioport_base + UART_MODEM_CONTROL);
	// full setup
	atomic_set(&serial->enabled, 1);

	spin_unlock_irqrestore(&serial->lock, flags);

	return 0;
}

static inline int
check_line_status(u8 status)
{
	if (status &
	(LINE_OVERRUN | LINE_PARITY_ERROR | LINE_FRAMING_ERROR |
	LINE_BREAK | LINE_IMPENDING_ERROR)) {
		pr_err("unhandled status: %x\n", status);
		return -EINVAL;
	}
	return 0;
}

// called when
// 1. after reading data from sin kfifo
// 2. interrupt happend
static ssize_t
serial_read_kickoff(struct serial_info *serial)
{
	int err;
	char ch;
	u8 status;
	ssize_t count;

	count = 0;
	while (1) {
		status = inb(serial->ioport_base + UART_LINE_STATUS);
		err = check_line_status(status);
		if (err)
			return err;
		if (!(status & LINE_DATA_READY))
			break;
		if (kfifo_is_full(&serial->sin)) // can not read anymore
			break;
		ch = inb(serial->ioport_base + UART_READ);
		kfifo_in(&serial->sin, &ch, 1);
		count++;
	}

	wake_up_interruptible(&serial->wq_in);
	// pr_info("read_kickoff: %d\n", count);
	return 0;
}

// called when
// 1. after writing data to sout kfifo
// 2. interrupt happened
static ssize_t
serial_write_kickoff(struct serial_info *serial)
{
	int err;
	char ch;
	u8 status;
	ssize_t count;

	count = 0;
	while (1) {
		status = inb(serial->ioport_base + UART_LINE_STATUS);
		err = check_line_status(status);
		if (err)
			return err;
		if (!(status & LINE_REGISTER_EMPTY))
			break;
		if (kfifo_is_empty(&serial->sout)) // can not write anymore
			break;
		kfifo_out(&serial->sout, &ch, 1);
		outb(ch, serial->ioport_base + UART_WRITE);
		count++;
	}

	wake_up_interruptible(&serial->wq_out);
	// pr_info("write_kickoff: %d\n", count);
	return 0;
}

static irqreturn_t
serial_handler(int irqno, void *dev_id)
{
	int err;
	struct serial_info *serial;
	u8 status, level;

	serial = dev_id;

	spin_lock(&serial->lock);

	status = inb(serial->ioport_base + UART_INTR_IDENTIFICATION);
	if (status & INTR_PENDING)
		goto end;
	level = (status >> 1) & 0x3;
	if (level == INTR_RECIEVE_LINE_STATUS) {
		pr_err("recieve line status: %x\n", status);
		BUG();
	} else if (level == INTR_DATA_AVAILABLE) {
		err = serial_read_kickoff(serial);
		if (err < 0) {
			pr_err("serial_read_kickoff failed: %d\n", err);
			BUG();
		}
	} else if (level == INTR_REGISTER_EMPTY) {
		err = serial_write_kickoff(serial);
		if (err < 0) {
			pr_err("serial_write_kickoff failed: %d\n", err);
			BUG();
		}
	} else if (level == INTR_MODEM_STATUS) {
		pr_err("recieve modem status: %x\n", status);
		BUG();
	} else {
		pr_err("unknown level: %d\n", level);
		BUG();
	}

end:
	spin_unlock(&serial->lock);

	return IRQ_HANDLED;
}

static int
dev_open(struct inode *inode, struct file *file)
{
	struct serial_info *serial;

	serial = container_of(inode->i_cdev, struct serial_info, cdev);
	file->private_data = serial;

	return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

#define kfifo_is_full_spinlocked(fifo, lock) \
({ \
	unsigned long __flags; \
	bool __ret; \
	spin_lock_irqsave(lock, __flags); \
	__ret = kfifo_is_full(fifo); \
	spin_unlock_irqrestore(lock, __flags); \
	__ret; \
})

static ssize_t
dev_read(struct file *file,
	char __user *user_buffer,
	size_t size, loff_t *offset)
{
	int err, i;
	unsigned long flags;
	struct serial_info *serial;
	size_t count;

	serial = file->private_data;
	if (atomic_read(&serial->enabled) != 1)
		return -EBUSY;

	mutex_lock(&serial->read);

	err = count = 0;
	while (size) {
		size_t unread, __count;
		char buf[BUF_SIZE];

		// peek from kfifo
		spin_lock_irqsave(&serial->lock, flags);

		if (kfifo_is_empty(&serial->sin) && count) {
			spin_unlock_irqrestore(&serial->lock, flags);
			break;
		}
		while (kfifo_is_empty(&serial->sin)) {
			spin_unlock_irqrestore(&serial->lock, flags);
			wait_event_interruptible(serial->wq_in,
				!kfifo_is_empty_spinlocked(&serial->sin,
							&serial->lock));
			spin_lock_irqsave(&serial->lock, flags);
		}

		__count = min((size_t)BUF_SIZE, size);
		__count = kfifo_out_peek(&serial->sin, buf, __count);

		spin_unlock_irqrestore(&serial->lock, flags);

		// copy to user
		unread = copy_to_user(user_buffer, buf, __count);
		if (unread == __count) {
			err = count ? 0 : -EFAULT;
			break;
		}
		__count -= unread;

		// update kfifo
		spin_lock_irqsave(&serial->lock, flags);

		for (i = 0 ; i < __count ; i++)
			kfifo_skip(&serial->sin);
		user_buffer += __count;
		count += __count;
		size -= __count;
		// pr_info("read: %d\n", __count);

		err = serial_read_kickoff(serial);
		if (err < 0) {
			pr_err("serial_read_kickoff failed: %d\n", err);
			BUG();
		}

		spin_unlock_irqrestore(&serial->lock, flags);
	}

	mutex_unlock(&serial->read);

	// pr_info("read ret: %d\n", err ? err : count);
	return err ? err : count;
}

static ssize_t
dev_write(struct file *file,
	const char __user *user_buffer,
	size_t size, loff_t *offset)
{
	int err;
	unsigned long flags;
	struct serial_info *serial;
	size_t count;

	serial = file->private_data;
	if (atomic_read(&serial->enabled) != 1)
		return -EBUSY;

	mutex_lock(&serial->write);

	err = count = 0;
	while (size) {
		size_t unwrite, __count;
		char buf[BUF_SIZE];

		// write from user
		__count = min_t(size_t, BUF_SIZE, size);
		unwrite = copy_from_user(buf, user_buffer, __count);
		if (unwrite == __count) {
			err = count ? 0 : -EFAULT;
			break;
		}

		// put into kfifo
		spin_lock_irqsave(&serial->lock, flags);

		if (kfifo_is_full(&serial->sout) && count) {
			spin_unlock_irqrestore(&serial->lock, flags);
			break;
		}

		while (kfifo_is_full(&serial->sout)) {
			spin_unlock_irqrestore(&serial->lock, flags);
			wait_event_interruptible(serial->wq_out,
				!kfifo_is_full_spinlocked(&serial->sout,
							&serial->lock));
			spin_lock_irqsave(&serial->lock, flags);
		}

		__count = kfifo_in(&serial->sout, buf, __count);
		user_buffer += __count;
		count += __count;
		size -= __count;
		// pr_info("write: %d\n", __count);

		err = serial_write_kickoff(serial);
		if (err < 0) {
			pr_err("serial_write_kickoff failed: %d\n", err);
			BUG();
		}

		spin_unlock_irqrestore(&serial->lock, flags);
	}

	mutex_unlock(&serial->write);

	// pr_info("write ret: %d\n", err ? err : count);
	return err ? err : count;
}

static long
dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
	struct serial_info *serial;
	struct uart16550_line_info line;

	serial = file->private_data;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		if (copy_from_user(
			&line, (void __user *)arg, sizeof(line)) != 0) {
			err = -EFAULT;
			break;
		}
		err = serial_setup(serial, &line);
		break;
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

const struct file_operations dev_fops = {
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
	.unlocked_ioctl = dev_ioctl,
};

static inline int
COM1_init(void)
{
	int err;

	if (option == OPTION_COM1
	    || option == OPTION_BOTH) {
		// disable intr
		outb(0x00, serial[0].ioport_base + UART_INTR_ENABLE);
		err = register_chrdev_region(
			MKDEV(major, 0), 1, MODULE_NAME);
		if (err)
			goto cleanup_CHRDEV;
		cdev_init(&serial[0].cdev, &dev_fops);
		err = cdev_add(&serial[0].cdev, MKDEV(major, 0), 1);
		if (err)
			goto cleanup_CDEV;
		if (!request_region(0x3f8, 8, MODULE_NAME)) {
			err = -ENODEV;
			goto cleanup_IOPORTS;
		}
		err = request_irq(4, serial_handler,
			0, MODULE_NAME, &serial[0]);
		if (err)
			goto cleanup_INTR;
	}

	return 0;
cleanup_INTR:
	release_region(0x3f8, 8);
cleanup_IOPORTS:
	cdev_del(&serial[0].cdev);
cleanup_CDEV:
	unregister_chrdev_region(MKDEV(major, 0), 1);
cleanup_CHRDEV:
	return err;
}

static inline void
COM1_free(void)
{
	if (option == OPTION_COM1
	    || option == OPTION_BOTH) {
		free_irq(4, &serial[0]);
		release_region(0x3f8, 8);
		unregister_chrdev_region(MKDEV(major, 0), 1);
		cdev_del(&serial[0].cdev);
	}
}

static inline int
COM2_init(void)
{
	int err;

	if (option == OPTION_COM2
	    || option == OPTION_BOTH) {
		// disable intr
		outb(0x00, serial[1].ioport_base + UART_INTR_ENABLE);
		err = register_chrdev_region(
			MKDEV(major, 1), 1, MODULE_NAME);
		if (err)
			goto cleanup_CHRDEV;
		cdev_init(&serial[1].cdev, &dev_fops);
		err = cdev_add(&serial[1].cdev, MKDEV(major, 1), 1);
		if (err)
			goto cleanup_CDEV;
		if (!request_region(0x2f8, 8, MODULE_NAME)) {
			err = -ENODEV;
			goto cleanup_IOPORTS;
		}
		err = request_irq(3, serial_handler,
			0, MODULE_NAME, &serial[1]);
		if (err)
			goto cleanup_INTR;
	}

	return 0;
cleanup_INTR:
	release_region(0x2f8, 8);
cleanup_IOPORTS:
	cdev_del(&serial[1].cdev);
cleanup_CDEV:
	unregister_chrdev_region(MKDEV(major, 1), 1);
cleanup_CHRDEV:
	return err;
}

static inline void
COM2_free(void)
{
	if (option == OPTION_COM2
	    || option == OPTION_BOTH) {
		free_irq(3, &serial[1]);
		release_region(0x2f8, 8);
		cdev_del(&serial[1].cdev);
		unregister_chrdev_region(MKDEV(major, 1), 1);
	}
}


static int
uart_init(void)
{
	int err, i;

	// init serial_infos
	serial[0].ioport_base = 0x3f8;
	serial[1].ioport_base = 0x2f8;
	for (i = 0 ; i < 2 ; i++) {
		spin_lock_init(&serial[i].lock);
		mutex_init(&serial[i].read);
		mutex_init(&serial[i].write);
		init_waitqueue_head(&serial[i].wq_in);
		init_waitqueue_head(&serial[i].wq_out);
		atomic_set(&serial[i].enabled, 0);
		INIT_KFIFO(serial[i].sin);
		INIT_KFIFO(serial[i].sout);
	}
	// setup devices
	err = COM1_init();
	if (err)
		goto cleanup_COM1;
	err = COM2_init();
	if (err)
		goto cleanup_COM2;

	return 0;
cleanup_COM2:
	COM1_free();
cleanup_COM1:
	return err;
}

static void uart_exit(void)
{
	COM1_free();
	COM2_free();
}

module_init(uart_init);
module_exit(uart_exit);
MODULE_DESCRIPTION("Linux uart16550 driver");
MODULE_AUTHOR("Sundi Guan <913887524@qq.com>");
MODULE_LICENSE("GPL v2");
