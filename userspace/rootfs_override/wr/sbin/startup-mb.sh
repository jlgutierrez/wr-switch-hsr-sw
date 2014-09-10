#!/bin/ash
export WR_HOME="/wr"

# Get parameter from kernel commandline
for arg in $(cat /proc/cmdline); do
	echo $arg | grep -q "wr_nic.macaddr" ;
	if [ $? == 0 ]; then
		val=$(echo $arg | cut -d= -f2);
	fi;
done

# Obtain the type of FPGA (LX130XT or LX240XT)
tfpga=$($WR_HOME/bin/wrs_version -F)

# TODO: Update wrsw_version to read this value from DF.
scb_ver=33
if mtdinfo -a | grep -A 1 dataflash | grep 264 &> /dev/null; then
	scb_ver=34
fi

$WR_HOME/bin/load-virtex $WR_HOME/lib/firmware/18p_mb-${tfpga}.bin
$WR_HOME/bin/load-lm32 $WR_HOME/lib/firmware/rt_cpu.elf scb_ver=${scb_ver}
insmod $WR_HOME/lib/modules/at91_softpwm.ko
insmod $WR_HOME/lib/modules/wr_vic.ko
insmod $WR_HOME/lib/modules/wr-nic.ko macaddr=$val
insmod $WR_HOME/lib/modules/wr_rtu.ko
insmod $WR_HOME/lib/modules/wr_pstats.ko pstats_nports=18
$WR_HOME/sbin/start-daemons.sh

