// SPDX-License-Identifier: GPL-2.0+
/*
 * ssr.c - RAID I Virtual Block Device
 *
 * Author: Sundi Guan <913887524@qq.com>
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/wait.h>
#include <linux/crc32.h>

#include "ssr.h"
#include "crc.h"

static struct block_device *bdev[2];
static const char *bdev_name[2] = { PHYSICAL_DISK1_NAME, PHYSICAL_DISK2_NAME };

struct ssr_dev {
	struct blk_mq_tag_set tag_set;
	struct request_queue *queue;
	struct gendisk *gd;
	struct workqueue_struct *wq;
};

struct ssr_work {
	struct bio *bio;
	struct work_struct work;
};

static struct ssr_dev sdev;

static int ssr_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ssr_release(struct gendisk *gd, fmode_t mode)
{
}

static void ssr_end_io(struct bio *bio)
{
	complete(bio->bi_private);
}

static inline void ssr_submit_bio_noacct_wait(struct bio *bio)
{
	struct completion comp;

	init_completion(&comp);
	bio->bi_end_io = ssr_end_io;
	bio->bi_private = &comp;
	submit_bio_noacct(bio);

	wait_for_completion(&comp);
}

static inline int ssr_read(struct bio_vec *bvec, const sector_t sec)
{
	int i, j, chk_bitmap, chk_mask;
	size_t len, offset;
	char *buf;
	bool need_recover;

	len = bvec->bv_len;
	BUG_ON(len % SECTOR_SIZE);
	BUG_ON(bvec->bv_offset + len > PAGE_SIZE);
	chk_mask = (1 << (len / SECTOR_SIZE)) - 1;
	chk_bitmap = 0;
	need_recover = false;

	for (i = 0; i < 2; i++) {
		u32 *crc_iter;
		void *data_buf, *crc_buf;
		struct page *data_page, *crc_page;
		struct bio *data_bio, *crc_bio;

		// read data bio
		data_bio = bio_alloc(GFP_NOIO, 1);
		bio_set_dev(data_bio, bdev[i]);
		data_bio->bi_iter.bi_sector = sec;
		data_bio->bi_opf = REQ_OP_READ;
		data_page = alloc_page(GFP_NOIO);
		bio_add_page(data_bio, data_page, len, 0);
		ssr_submit_bio_noacct_wait(data_bio);
		// read crc bio
		crc_bio = bio_alloc(GFP_NOIO, 1);
		bio_set_dev(crc_bio, bdev[i]);
		crc_bio->bi_iter.bi_sector = crc_sec(sec);
		crc_bio->bi_opf = REQ_OP_READ;
		crc_page = alloc_page(GFP_NOIO);
		bio_add_page(crc_bio, crc_page, 2 * SECTOR_SIZE, 0);
		ssr_submit_bio_noacct_wait(crc_bio);
		// check all crc
		buf = kmap_atomic(bvec->bv_page);
		data_buf = kmap_atomic(data_page);
		crc_buf = kmap_atomic(crc_page);
		crc_iter = crc_ptr(crc_buf, sec);
		for (offset = 0, j = 0; offset < len;
		     offset += SECTOR_SIZE, j++, crc_iter++) {
			u32 crc_maybe_wrong;

			crc_maybe_wrong = crc((char *)data_buf + offset);
			if (crc_maybe_wrong != *crc_iter) { // check failed
				pr_info("check failed!: %x <-> %x\n",
					crc_maybe_wrong, *crc_iter);
				need_recover = true;
			} else { // check passed
				chk_bitmap |= 1 << j;
				memcpy(buf + bvec->bv_offset + offset,
				       (char *)data_buf + offset, SECTOR_SIZE);
			}
		}
		kunmap_atomic(crc_buf);
		kunmap_atomic(data_buf);
		kunmap_atomic(buf);
		// recycle
		bio_free_pages(data_bio);
		bio_put(data_bio);
		bio_free_pages(crc_bio);
		bio_put(crc_bio);
	}

	if (!need_recover || chk_mask != chk_bitmap)
		return chk_mask != chk_bitmap;
	// need recover and data is integrated
	// force to flush all data
	for (i = 0; i < 2; i++) {
		void *data_buf;
		struct page *data_page;
		struct bio *data_bio;

		// write data bio
		data_bio = bio_alloc(GFP_NOIO, 1);
		bio_set_dev(data_bio, bdev[i]);
		data_bio->bi_iter.bi_sector = sec;
		data_bio->bi_opf = REQ_OP_WRITE;
		data_page = alloc_page(GFP_NOIO);
		buf = kmap_atomic(bvec->bv_page);
		data_buf = kmap_atomic(data_page);
		memcpy(data_buf, buf + bvec->bv_offset, len);
		kunmap_atomic(data_buf);
		kunmap_atomic(buf);
		bio_add_page(data_bio, data_page, len, 0);
		ssr_submit_bio_noacct_wait(data_bio);
		// recycle
		bio_free_pages(data_bio);
		bio_put(data_bio);
	}
	return 0;
}

static inline int ssr_write(struct bio_vec *bvec, const sector_t sec)
{
	int i;
	size_t len, offset;
	char *buf;

	len = bvec->bv_len;
	BUG_ON(len % SECTOR_SIZE);
	BUG_ON(bvec->bv_offset + len > PAGE_SIZE);

	for (i = 0; i < 2; i++) {
		u32 *crc_iter;
		void *data_buf, *crc_buf;
		struct page *data_page, *crc_page;
		struct bio *data_bio, *crc_bio;

		// write data bio
		data_bio = bio_alloc(GFP_NOIO, 1);
		bio_set_dev(data_bio, bdev[i]);
		data_bio->bi_iter.bi_sector = sec;
		data_bio->bi_opf = REQ_OP_WRITE;
		data_page = alloc_page(GFP_NOIO);
		buf = kmap_atomic(bvec->bv_page);
		data_buf = kmap_atomic(data_page);
		memcpy(data_buf, buf + bvec->bv_offset, len);
		kunmap_atomic(data_buf);
		kunmap_atomic(buf);
		bio_add_page(data_bio, data_page, len, 0);
		ssr_submit_bio_noacct_wait(data_bio);
		// read crc bio
		crc_bio = bio_alloc(GFP_NOIO, 1);
		bio_set_dev(crc_bio, bdev[i]);
		crc_bio->bi_iter.bi_sector = crc_sec(sec);
		crc_bio->bi_opf = REQ_OP_READ;
		crc_page = alloc_page(GFP_NOIO);
		bio_add_page(crc_bio, crc_page, 2 * SECTOR_SIZE, 0);
		ssr_submit_bio_noacct_wait(crc_bio);
		// calculare crc
		buf = kmap_atomic(bvec->bv_page);
		crc_buf = kmap_atomic(crc_page);
		crc_iter = crc_ptr(crc_buf, sec);
		for (offset = 0; offset < len;
		     offset += SECTOR_SIZE, crc_iter++) {
			*crc_iter = crc(buf + bvec->bv_offset + offset);
			// pr_info("crc: %x\n", *crc_iter);
		}
		kunmap_atomic(crc_buf);
		kunmap_atomic(buf);
		// write back crc bio
		bio_reset(crc_bio);
		bio_set_dev(crc_bio, bdev[i]);
		crc_bio->bi_iter.bi_sector = crc_sec(sec);
		crc_bio->bi_opf = REQ_OP_WRITE;
		bio_add_page(crc_bio, crc_page, 2 * SECTOR_SIZE, 0);
		ssr_submit_bio_noacct_wait(crc_bio);
		// recycle
		bio_free_pages(data_bio);
		bio_put(data_bio);
		bio_free_pages(crc_bio);
		bio_put(crc_bio);
	}

	return 0;
}

static void ssr_work_handler(struct work_struct *ws)
{
	int err;
	struct bio *bio;
	struct bio_vec bvec, in_bvec;
	struct bvec_iter iter;
	struct ssr_work *sw;

	err = 0;
	sw = container_of(ws, struct ssr_work, work);
	bio = sw->bio;

	bio_for_each_bvec(bvec, bio, iter) {
		int dir;
		sector_t sec;
		unsigned long start, end, offset;

		sec = iter.bi_sector;
		dir = bio_data_dir(bio);
		start = bvec.bv_offset;
		end = start + bvec.bv_len;

		for (offset = start; offset < end;) {
			size_t avail_bytes;
			// calculate available bytes
			if (offset % PAGE_SIZE == 0)
				avail_bytes =
					min(offset + PAGE_SIZE, end) - offset;
			else
				avail_bytes =
					min(ALIGN(offset, PAGE_SIZE), end) -
					offset;
			in_bvec = (struct bio_vec){
				.bv_len = avail_bytes,
				.bv_offset = offset % PAGE_SIZE,
				.bv_page = &bvec.bv_page[offset / PAGE_SIZE],
			};
			// send to read/write
			if (dir == READ)
				err = ssr_read(&in_bvec, sec);
			else
				err = ssr_write(&in_bvec, sec);
			if (err)
				break;
			// update offset
			offset += avail_bytes;
			sec += avail_bytes / SECTOR_SIZE;
		}
		if (err)
			break;
	}

	bio->bi_status = err ? BLK_STS_IOERR : BLK_STS_OK;
	bio_endio(bio);

	kfree(sw);
}

static blk_qc_t ssr_submit_bio(struct bio *bio)
{
	struct ssr_work *sw;
	struct ssr_dev *dev;

	sw = kmalloc(sizeof(struct ssr_work), GFP_KERNEL);
	sw->bio = bio;
	INIT_WORK(&sw->work, ssr_work_handler);

	dev = bio->bi_disk->private_data;
	queue_work(dev->wq, &sw->work);
	schedule_work(&sw->work);

	return BLK_QC_T_NONE;
}

static const struct block_device_operations ssr_ops = {
	.open = ssr_open,
	.release = ssr_release,
	.submit_bio = ssr_submit_bio,
};

static blk_status_t block_request(struct blk_mq_hw_ctx *hctx,
				  const struct blk_mq_queue_data *bd)
{
	struct request *rq;

	rq = bd->rq;
	blk_mq_start_request(rq);
	pr_err("block request not support\n");
	blk_mq_end_request(rq, BLK_STS_IOERR);

	return BLK_STS_IOERR;
}

static struct blk_mq_ops queue_ops = {
	.queue_rq = block_request,
};

static int create_block_device(struct ssr_dev *dev)
{
	int err;

	dev->tag_set.ops = &queue_ops;
	dev->tag_set.nr_hw_queues = 1;
	dev->tag_set.queue_depth = 128;
	dev->tag_set.numa_node = NUMA_NO_NODE;
	dev->tag_set.cmd_size = 0;
	dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	err = blk_mq_alloc_tag_set(&dev->tag_set);
	if (err) {
		pr_err("blk_mq_alloc_tag_set failed: %d\n", err);
		goto out_alloc_tag_set;
	}

	dev->queue = blk_mq_init_queue(&dev->tag_set);
	if (IS_ERR(dev->queue)) {
		err = PTR_ERR(dev->queue);
		pr_err("blk_mq_init_queue failed: %d\n", err);
		goto out_init_queue;
	}
	blk_queue_logical_block_size(dev->queue, KERNEL_SECTOR_SIZE);
	dev->queue->queuedata = dev;

	dev->gd = alloc_disk(SSR_NUM_MINORS);
	if (!dev->gd) {
		err = -ENOMEM;
		pr_err("alloc_disk failed: %d\n", err);
		goto out_alloc_gd;
	}
	dev->gd->major = SSR_MAJOR;
	dev->gd->first_minor = SSR_FIRST_MINOR;
	dev->gd->fops = &ssr_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "ssr");
	set_capacity(dev->gd, LOGICAL_DISK_SECTORS);
	add_disk(dev->gd);

	return 0;
out_alloc_gd:
	blk_cleanup_queue(dev->queue);
out_init_queue:
	blk_mq_free_tag_set(&dev->tag_set);
out_alloc_tag_set:
	return err;
}

static void delete_block_device(struct ssr_dev *dev)
{
	del_gendisk(dev->gd);
	put_disk(dev->gd);

	blk_cleanup_queue(dev->queue);
	blk_mq_free_tag_set(&dev->tag_set);
}

static int __init ssr_init(void)
{
	int err, i;

	sdev.wq = create_workqueue("ssr");
	if (sdev.wq == NULL) {
		err = -ENOMEM;
		pr_err("create_workqueue failed: %d\n", err);
		goto out_alloc_wq;
	}

	err = register_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
	if (err) {
		pr_err("register_blkdev failed: %d\n", err);
		goto out_reg_blk;
	}

	err = create_block_device(&sdev);
	if (err) {
		pr_err("create_block_device failed: %d\n", err);
		goto out_create_blk;
	}

	for (i = 0; i < 2; i++) {
		bdev[i] = blkdev_get_by_path(
			bdev_name[i], FMODE_READ | FMODE_WRITE | FMODE_EXCL,
			THIS_MODULE);
		if (IS_ERR(bdev[i])) {
			i--;
			for (; i >= 0; i--)
				blkdev_put(bdev[i], FMODE_READ | FMODE_WRITE |
							    FMODE_EXCL);
			goto out_open_disk;
		}
	}

	return 0;
out_open_disk:
	delete_block_device(&sdev);
out_create_blk:
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
out_reg_blk:
	destroy_workqueue(sdev.wq);
out_alloc_wq:
	return err;
}

static void __exit ssr_exit(void)
{
	int i;

	flush_workqueue(sdev.wq);
	destroy_workqueue(sdev.wq);

	for (i = 0; i < 2; i++)
		blkdev_put(bdev[i], FMODE_READ | FMODE_WRITE | FMODE_EXCL);

	delete_block_device(&sdev);
	unregister_blkdev(SSR_MAJOR, LOGICAL_DISK_NAME);
}

module_init(ssr_init);
module_exit(ssr_exit);

MODULE_AUTHOR("Sundi Guan <913887524@qq.com>");
MODULE_DESCRIPTION("RAID II device");
MODULE_LICENSE("GPL");
