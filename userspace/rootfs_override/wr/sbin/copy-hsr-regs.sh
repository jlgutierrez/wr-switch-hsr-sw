#!/bin/ash
export WR_HOME="/wr"

echo "Reading HSR MAC address from endpoint"
HSR_MAC_LOW=$(devmem 0x10030424)
HSR_MAC_HIGH=$(devmem 0x10030428)

devmem 0x10061004 32 $HSR_MAC_LOW
devmem 0x10061008 32 $HSR_MAC_HIGH
echo "HSR MAC address copied to HSR_LRE_REGS"

echo "Adding HSR Supervision Multicast to RTU table"
/usr/wr/bin/rtu_stat add 01:15:4e:00:01:00 5 2>&1


