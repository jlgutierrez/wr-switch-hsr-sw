/*
 * hardware-specific definitions for the White Rabbit NIC
 *
 * Copyright (C) 2010 CERN (www.cern.ch)
 * Author: Alessandro Rubini <rubini@gnudd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __WR_NIC_HARDWARE_H__
#define __WR_NIC_HARDWARE_H__

/* Our host CPU is this one, no way out of it */
#include <mach/at91sam9263.h>

/* The interrupt is one of those managed by our WRVIC device */
#define WRN_IRQ_BASE		192
#define WRN_IRQ_PPSG		(WRN_IRQ_BASE + 0)
#define WRN_IRQ_NIC		(WRN_IRQ_BASE + 1)
#define WRN_IRQ_RTU		(WRN_IRQ_BASE + 2)
#define WRN_IRQ_RTUT		(WRN_IRQ_BASE + 3)
#define WRN_IRQ_TSTAMP		(WRN_IRQ_BASE + 4)

/* This is the base address of all the FPGA regions (EBI1, CS0) */
#define FPGA_BASE_ADDRESS 0x70000000

/* The memory map is split in several blocks, each of them 64kB */
#define FPGA_BLOCK_SIZE		0x10000 /* for ioremap */
#define __FPGA_BLOCK_TO_ADDR(block)			\
	(FPGA_BASE_ADDRESS + (block) * FPGA_BLOCK_SIZE)

/* I number fpga blocks, to handle all the base addresses as an array */
enum fpga_blocks {
	WRN_BLOCK_REVID		= 0x00,	/* Not used here */
	WRN_BLOCK_GPIO		= 0x01,	/* Not used here */
	WRN_BLOCK_SPIM		= 0x02,	/* Not used here */
	WRN_BLOCK_VIC		= 0x03,	/* Separate module */
	WRN_BLOCK_EP_UP0	= 0x04,
	WRN_BLOCK_EP_UP1	= 0x05,
	WRN_BLOCK_EP_DP0	= 0x06,
	WRN_BLOCK_EP_DP1	= 0x07,
	WRN_BLOCK_EP_DP2	= 0x08,
	WRN_BLOCK_EP_DP3	= 0x09,
	WRN_BLOCK_EP_DP4	= 0x0a,
	WRN_BLOCK_EP_DP5	= 0x0b,
	WRN_BLOCK_EP_DP6	= 0x0c,
	WRN_BLOCK_EP_DP7	= 0x0d,
	WRN_BLOCK_PPSG		= 0x0e,	/* pps.c */
	WRN_BLOCK_CALIBRATOR	= 0x0f,	/* dmtd.c */
	WRN_BLOCK_RTU		= 0x10,	/* Separate driver */
	WRN_BLOCK_RTU_TESTUNIT	= 0x11,	/* Separate driver */
	WRN_BLOCK_NIC		= 0x12,
	WRN_BLOCK_TSTAMP	= 0x13,	/* timestamp.c */

	WRN_NBLOCKS	/* number of blocks, for array size */
};
/* In addition to the above enumeration, mark out endpoints */
#define WRN_NR_ENDPOINTS		10
#define WRN_FIRST_EP			WRN_BLOCK_EP_UP0
#define WRN_LAST_EP			WRN_BLOCK_EP_DP7
#define WRN_NR_UPLINK (WRN_BLOCK_EP_DP0 - WRN_BLOCK_EP_UP0)

/* Hardware addresses are derived from the block numbers */
#define FPGA_BASE(name)		__FPGA_BLOCK_TO_ADDR(WRN_BLOCK_ ## name)

/* And this bad thing exists to get the block from the address */
#define __FPGA_BASE_TO_NR(add) (((add) - FPGA_BASE_ADDRESS) / FPGA_BLOCK_SIZE)

/* 8 tx and 8 rx descriptors */
#define WRN_NR_DESC	8
#define WRN_NR_TXDESC	WRN_NR_DESC
#define WRN_NR_RXDESC	WRN_NR_DESC

/* Magic number for endpoint */
#define WRN_EP_MAGIC 0xcafebabe

/*
 * The following headers include the register lists, and have been
 * generated by wbgen from .wb source files in svn
 */
#include "../wbgen-regs/endpoint-regs.h"
#include "../wbgen-regs/ppsg-regs.h"
#include "../wbgen-regs/calib-regs.h"
#include "../wbgen-regs/nic-regs.h"
#include "../wbgen-regs/tstamp-regs.h"

/*
 * To make thins easier, define the descriptor structures, for tx and rx
 * Use functions in nic-mem.h to get pointes to them
 */
struct wrn_txd {
	uint32_t tx1;
	uint32_t tx2;
	uint32_t tx3;
	uint32_t unused;
};

struct wrn_rxd {
	uint32_t rx1;
	uint32_t rx2;
	uint32_t rx3;
	uint32_t unused;
};

/* Some more constants */
#define WRN_MTU 1540

#define WRN_DDATA_OFFSET 2 /* data in descriptors is offset by that much */

#endif /* __WR_NIC_HARDWARE_H__ */
