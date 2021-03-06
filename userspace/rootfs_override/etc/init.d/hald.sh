#!/bin/sh

dotconfig=/wr/etc/dot-config

start() {
    echo -n "Starting HAL daemon: "

    if [ -f $dotconfig ]; then
	. $dotconfig
    else
	echo "$0 unable to source dot-config ($dotconfig)!"
    fi

    WRS_LOG=$CONFIG_WRS_LOG_HAL

    # if empty turn it to /dev/null
    if [ -z $WRS_LOG ]; then
	WRS_LOG="/dev/null";
    fi

    # if a pathname, use it
    if echo "$WRS_LOG" | grep / > /dev/null; then
	eval LOGPIPE=\" \> $WRS_LOG 2\>\&1 \";
    else
	# not a pathname: use verbatim
	eval LOGPIPE=\" 2\>\&1 \| logger -t wr-switch -p $WRS_LOG\"
    fi

# be carefull with pidof, no running script should have the same name as process
    if pidof wrsw_hal > /dev/null; then
	# wrsw_hal already running
	echo "Failed (already running?)"
    else
	eval /wr/bin/wrsw_hal $LOGPIPE \&
	echo "OK"
    fi
}

stop() {
    echo -n "Stopping HAL "
    start-stop-daemon -K -q --exec /wr/bin/wrsw_hal
    if [ $? -eq 0 ]; then
	echo "OK"
    else
	echo "Failed"
    fi
}

restart() {
    stop
    # give HAL time to stop his child
    sleep 1
    start
}

case "$1" in
  start)
	start
	;;
  stop)
	stop
	;;
  restart|reload)
	restart
	;;
  *)
	echo $"Usage: $0 {start|stop|restart}"
	exit 1
	;;
esac
