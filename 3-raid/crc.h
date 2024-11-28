/* SPDX-License-Identifier: GPL-2.0+
 *
 * crc.h - CRC helper functions
 *
 * Author: Sundi Guan <913887524@qq.com>
 */

#ifndef CRC_H_
#define CRC_H_ 1

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/crc32.h>

#include "ssr.h"

static inline u32 crc(const unsigned char *c)
{
	return crc32(0, c, SECTOR_SIZE);
}

static inline sector_t crc_sec(sector_t sec)
{
	return LOGICAL_DISK_SECTORS + (sec * sizeof(u32) / SECTOR_SIZE);
}

static inline unsigned long crc_offset(sector_t sec)
{
	return sec * sizeof(u32) % SECTOR_SIZE;
}

static inline u32 *crc_ptr(void *buf, sector_t sec)
{
	return (void *)((char *)buf + crc_offset(sec));
}

#endif
