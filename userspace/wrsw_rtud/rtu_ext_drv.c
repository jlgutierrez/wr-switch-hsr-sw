/*
 * White Rabbit RTU (Routing Table Unit)
 * Copyright (C) 2010, CERN.
 *
 * Version:     wrsw_rtud v1.1
 *
 * Authors:     Maciej Lipinski (maciej.lipinski@cern.ch)
 *
 * Description: RTU driver module in user space to control extended RTU features
 *
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <switch_hw.h>
#include <hal_client.h>

#include <fpga_io.h>
#include <regs/rtu-regs.h>

#include "rtu_ext_drv.h"
#include "wr_rtu.h"

int rtux_init(void)
{
	rtux_set_hp_prio_mask(0x00 /*hp prio mask */ );	// no HP

	rtux_set_feature_ctrl(0 /*mr */ ,
			      1 /*mac_ptp */ ,
			      1 /*mac_ll */ ,
			      0 /*mac_single */ ,
			      0 /*mac_range */ ,
			      1 /*mac_br */ ,
			      0 /*drop when full_match full */ );

	return 0;
}

#define rtu_rd(reg) \
	 _fpga_readl(FPGA_BASE_RTU + offsetof(struct RTU_WB, reg))

#define rtu_wr(reg, val) \
	 _fpga_writel(FPGA_BASE_RTU + offsetof(struct RTU_WB, reg), val)

static uint32_t get_mac_lo(uint8_t mac[ETH_ALEN])
{
	return
	    ((0xFF & mac[2]) << 24) |
	    ((0xFF & mac[3]) << 16) |
	    ((0xFF & mac[4]) << 8) | ((0xFF & mac[5]));
}

static uint32_t get_mac_hi(uint8_t mac[ETH_ALEN])
{
	return ((0xFF & mac[0]) << 8) | ((0xFF & mac[1]));
}

/**
 * \brief Configures a single MACs to be forwarded using fast-match (broadcast within VLAN)
 * @param mac_id    ID of the entry
 * @param valid     indicates whether it is valid (if not valid, the entry is removed
 * @param mac_lower MAC address
 */
void rtux_add_ff_mac_single(int mac_id, int valid, uint8_t mac[ETH_ALEN])
{
	uint32_t mac_hi = 0, mac_lo = 0;

	mac_lo = RTU_RX_FF_MAC_R0_LO_W(get_mac_lo(mac));
	mac_hi = RTU_RX_FF_MAC_R1_HI_ID_W(get_mac_hi(mac)) | RTU_RX_FF_MAC_R1_ID_W(mac_id) | 0 |	// type = 0
	    RTU_RX_FF_MAC_R1_VALID;

	rtu_wr(RX_FF_MAC_R0, mac_lo);
	rtu_wr(RX_FF_MAC_R1, mac_hi);

	TRACE(TRACE_INFO,
	      "RTU eXtension: set fast forward single mac (id=%d, valid=%d) of "
	      "%x:%x:%x:%x:%x:%x", mac_id, valid, mac[0], mac[1], mac[2],
	      mac[3], mac[4], mac[5]);
}

/**
 * \brief Configures a range of MACs to be forwarded using fast-match (broadcast within VLAN)
 * @param mac_id    ID of the entry
 * @param valid     indicates whether it is valid (if not valid, the entry is removed
 * @param mac_lower MAC with address that starts the range
 * @param mac_upper MAC with address that finishes the range
 */
void rtux_add_ff_mac_range(int mac_id, int valid, uint8_t mac_lower[ETH_ALEN],
			   uint8_t mac_upper[ETH_ALEN])
{
	uint32_t mac_hi = 0, mac_lo = 0;
	uint32_t m_mac_id = 0;	// modified mac id

	// writting lower boundary of the mac range
	m_mac_id = (~(1 << 7)) & mac_id;	// lower range (highest bit is low)

	mac_lo = RTU_RX_FF_MAC_R0_LO_W(get_mac_lo(mac_lower));
	mac_hi = RTU_RX_FF_MAC_R1_HI_ID_W(get_mac_hi(mac_lower)) | RTU_RX_FF_MAC_R1_ID_W(m_mac_id) | RTU_RX_FF_MAC_R1_TYPE |	// type = 1
	    RTU_RX_FF_MAC_R1_VALID;

	rtu_wr(RX_FF_MAC_R0, mac_lo);
	rtu_wr(RX_FF_MAC_R1, mac_hi);

	// writting upper boundary of the mac range
	m_mac_id = (1 << 7) | mac_id;	// upper range high (highest bit is high)

	mac_lo = RTU_RX_FF_MAC_R0_LO_W(get_mac_lo(mac_upper));
	mac_hi = RTU_RX_FF_MAC_R1_HI_ID_W(get_mac_hi(mac_upper)) | RTU_RX_FF_MAC_R1_ID_W(m_mac_id) | RTU_RX_FF_MAC_R1_TYPE |	// type = 1
	    RTU_RX_FF_MAC_R1_VALID;

	rtu_wr(RX_FF_MAC_R0, mac_lo);
	rtu_wr(RX_FF_MAC_R1, mac_hi);

	TRACE(TRACE_INFO,
	      "RTU eXtension: set fast forward mac range: (id=%d, valid=%d):",
	      mac_id, valid);
	TRACE(TRACE_INFO, "\t lower_mac = %x:%x:%x:%x:%x:%x", mac_lower[0],
	      mac_lower[1], mac_lower[2], mac_lower[3], mac_lower[4],
	      mac_lower[5]);
	TRACE(TRACE_INFO, "\t upper_mac = %x:%x:%x:%x:%x:%x", mac_upper[0],
	      mac_upper[1], mac_upper[2], mac_upper[3], mac_upper[4],
	      mac_upper[5]);
}

/**
 * \brief Configure mirroring of ports (currently bugy in GW- don't use)
 * @param mirror_src_mask indicates from which ports traffic should be mirrored
 * @param mirror_dst_mask indicates to which ports mirrored traffic should be sent
 * @param rx              indicates that traffic received to src port should be mirrored
 * @param tx              indicates that traffic transmitted to src port should be mirrored
 */
void rtux_set_port_mirror(uint32_t mirror_src_mask, uint32_t mirror_dst_mask,
			  int rx, int tx)
{
	uint32_t mp_src_rx = 0, mp_src_tx = 0, mp_dst = 0, mp_sel = 0;

	mp_dst = RTU_RX_MP_R1_MASK_W(mirror_dst_mask);
	mp_src_tx = 0;
	mp_src_rx = 0;

	mp_sel = 0;		// destinatioon (dst_src=0)
	rtu_wr(RX_MP_R0, mp_sel);
	rtu_wr(RX_MP_R1, mp_dst);

	if (rx)
		mp_src_rx = RTU_RX_MP_R1_MASK_W(mirror_src_mask);
	else
		mp_src_rx = 0;
	mp_sel = 0;
	mp_sel = RTU_RX_MP_R0_DST_SRC;	// source (dst_src=1), reception traffic (rx_tx=0)
	rtu_wr(RX_MP_R0, mp_sel);
	rtu_wr(RX_MP_R1, mp_src_rx);

	if (tx)
		mp_src_tx = RTU_RX_MP_R1_MASK_W(mirror_src_mask);
	else
		mp_src_tx = 0;
	mp_sel = 0;
	mp_sel = RTU_RX_MP_R0_DST_SRC | RTU_RX_MP_R0_RX_TX;
	//  source (dst_src=1), transmission traffic (rx_tx=1)
	rtu_wr(RX_MP_R0, mp_sel);
	rtu_wr(RX_MP_R1, mp_src_tx);

	TRACE(TRACE_INFO,
	      "\t mirror output port(s) mask                 (dst)    = 0x%x",
	      mp_dst);
	TRACE(TRACE_INFO,
	      "\t ingress traffic mirror source port(s) mask (src_rx) = 0x%x",
	      mp_src_rx);
	TRACE(TRACE_INFO,
	      "\t egress  traffic mirror source port(s) mask (src_tx) = 0x%x",
	      mp_src_tx);
}

/**
 * \brief Read the mask which which priorities are considered High Priority (this only
 *        concerns the traffic which is fast-forwarded)
 * @return mask with priorities (eg. 0x9 => priority 7 and 0 are considered HP)

 */
uint8_t rtux_get_hp_prio_mask()
{
	uint32_t val = 0;

	val = rtu_rd(RX_CTR);
	TRACE(TRACE_INFO,
	      "RTU eXtension: read hp priorities (for which priorities traffic is "
	      "considered HP),  mask[rd]=0x%x", RTU_RX_CTR_PRIO_MASK_R(val));
	return (uint8_t) RTU_RX_CTR_PRIO_MASK_R(val);
}

/**
 * \brief Set the mask which which priorities are considered High Priority (this only
 *        concerns the traffic which is fast-forwarded)
 * @param hp_prio_mask mask with priorities (eg. 0x9 => priority 7 and 0 are considered HP)

 */
void rtux_set_hp_prio_mask(uint8_t hp_prio_mask)
{
	uint32_t mask, val = 0;

	mask = rtu_rd(RX_CTR);
	mask =
	    RTU_RX_CTR_PRIO_MASK_W(hp_prio_mask) | (mask &
						    ~RTU_RX_CTR_PRIO_MASK_MASK);
	rtu_wr(RX_CTR, mask);
	val = rtu_rd(RX_CTR);
	TRACE(TRACE_INFO,
	      "RTU eXtension: set hp priorities (for which priorities traffic is "
	      "considered HP), mask[wr]=0x%x => mask[rd]=0x%x", mask,
	      RTU_RX_CTR_PRIO_MASK_R(val));
}

/**
 * \brief Read number of virtual port on which CPU is connected to SWcore
 * @return port number
 */
int rtux_get_cpu_port()
{
	uint32_t mask;
	int i = 0;

	mask = rtu_rd(CPU_PORT);

	TRACE(TRACE_INFO,
	      "RTU eXtension: reading mask indicating which (virtual) port is connected"
	      "to CPU mask=0x%x", RTU_CPU_PORT_MASK_R(mask));
	for (i = 0; i <= MAX_PORT + 1; i++) {
		if (mask & 0x1)
			return i;
		else
			mask = mask >> 1;
	}
	return -1;
}

/**
 * \brief Setting (enabling/disabling) fast forwarding (few cycles, using special
 *        fast-match engine) and features
 * @param mr         enable mirroring of ports (needs to be configured properly)
 * @param mac_ptp    enable fast forwarding of PTP (Ethernet mapping, MAC=01:1b:19:00:00:00, wild card)
 * @param mac_ll     enable fast forwarding of Reserved MACs (wild card)
 * @param mac_single enable fast forwarding of MACs configured previously (boardcast within VLAN)
 * @param mac_range  enable fast forwarding of range of MACs configured previously (boardcast within VLAN)
 * @param mac_br     enable fast forwarding of range Broadcast traffic
 * @param at_fm      configure behavior of when the full match is to slow (0=drop, 1=broadcast within VLAN)
 */
void rtux_set_feature_ctrl(int mr, int mac_ptp, int mac_ll, int mac_single,
			   int mac_range, int mac_br, int at_fm)
{
	uint32_t mask;
	mask = rtu_rd(RX_CTR);
	mask = 0xFFFFFF80 & mask;

	if (mr)
		mask = RTU_RX_CTR_MR_ENA | mask;
	if (mac_ptp)
		mask = RTU_RX_CTR_FF_MAC_PTP | mask;
	if (mac_ll)
		mask = RTU_RX_CTR_FF_MAC_LL | mask;
	if (mac_single)
		mask = RTU_RX_CTR_FF_MAC_SINGLE | mask;
	if (mac_range)
		mask = RTU_RX_CTR_FF_MAC_RANGE | mask;
	//if (mac_br)
		//mask = RTU_RX_CTR_FF_MAC_BR | mask; // quitarlo para HSR-BR
	if (at_fm)
		mask = RTU_RX_CTR_AT_FMATCH_TOO_SLOW | mask;

	rtu_wr(RX_CTR, mask);
	rtux_disp_ctrl();
}

/**
 * \brief Sets forwarding of High Priority and/or unrecognized traffic to CPU (by default
 * 	  such traffic is not forwarded)
 * @param hp    flag indicateing High Prio traffic
 * @param unrec flag indicating unrecognized trafic)
 */
void rtux_set_fw_to_CPU(int hp, int unrec)
{
	uint32_t mask;
	mask = rtu_rd(RX_CTR);
	mask = 0xFFF0FFFF & mask;

	if (hp)
		mask = RTU_RX_CTR_HP_FW_CPU_ENA | mask;
	if (unrec)
		mask = RTU_RX_CTR_UREC_FW_CPU_ENA | mask;

	rtu_wr(RX_CTR, mask);
}

void rtux_disp_ctrl(void)
{
	uint32_t mask;
	mask = rtu_rd(RX_CTR);
	TRACE(TRACE_INFO, "RTU eXtension features (read):");
	if (RTU_RX_CTR_MR_ENA & mask) {
		TRACE(TRACE_INFO,
		      "\t (1 ) Port Mirroring                           - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t (1 ) Port Mirroring                           - disabled");
	}
	if (RTU_RX_CTR_FF_MAC_PTP & mask) {
		TRACE(TRACE_INFO,
		      "\t (2 ) PTP fast forward                         - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t (2 ) PTP fast forward                         - disabled");
	}
	if (RTU_RX_CTR_FF_MAC_LL & mask) {
		TRACE(TRACE_INFO,
		      "\t (4 ) Link-limited traffic (BPDU) fast forward - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t (4 ) Link-limited traffic (BPDU) fast forward - disabled");
	}
	if (RTU_RX_CTR_FF_MAC_SINGLE & mask) {
		TRACE(TRACE_INFO,
		      "\t (8 ) Single configured MACs fast forward      - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t (8 ) Single configured MACs fast forward      - disabled");
	}
	if (RTU_RX_CTR_FF_MAC_RANGE & mask) {
		TRACE(TRACE_INFO,
		      "\t (16) Range of configured MACs fast forward    - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t (16) Range of configured MACs fast forward    - disabled");
	}
	if (RTU_RX_CTR_FF_MAC_BR & mask) {
		TRACE(TRACE_INFO,
		      "\t (32) Broadcast fast forward                   - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t (32) Broadcast fast forward                   - disabled");
	}
	if (RTU_RX_CTR_AT_FMATCH_TOO_SLOW & mask) {
		TRACE(TRACE_INFO,
		      "\t (64) When fast match engine too slow          - braodcast processed frame");
	} else {
		TRACE(TRACE_INFO,
		      "\t (64) When fast match engine too slow          - drop processed frame");
	}
	if (RTU_RX_CTR_FORCE_FAST_MATCH_ENA & mask) {
		TRACE(TRACE_INFO,
		      "\t DBG  Force Fast Mach Mechanism                - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t DBG  Force Fast Mach Mechanism                - disabled");
	}
	if (RTU_RX_CTR_FORCE_FULL_MATCH_ENA & mask) {
		TRACE(TRACE_INFO,
		      "\t DBG  Force Full Mach Mechanism                - enabled");
	} else {
		TRACE(TRACE_INFO,
		      "\t DBG  Force Full Mach Mechanism                - disabled");
	}
}
