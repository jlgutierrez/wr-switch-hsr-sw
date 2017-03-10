#!/bin/ash

rm /tmp/hsr_rtu_redbox.list
/wr/bin/rtu_stat | grep DYNAMIC | awk -F ' ' '{ print $1,$2 }' | grep -v ' 1' | grep -v ' 2' | grep -v ' CPU' | grep -v ' ALL' | awk '{ print $1 }' >/tmp/hsr_rtu_redbox.list
sed -i 's/://g' /tmp/hsr_rtu_redbox.list
