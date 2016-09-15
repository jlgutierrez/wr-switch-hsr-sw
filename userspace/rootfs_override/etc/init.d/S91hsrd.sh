#!/bin/ash
#
# Starts lighttpd daemon.
#
start() {
 	echo -n "Starting hsrd daemon: "
	/usr/sbin/wrsw_hsrd /wr/etc/hsr.conf
	echo "OK"
}
stop() {
	echo -n "Stopping hsrd daemon: "
	killall wrsw_hsrd
	echo "OK"
}
restart() {
	stop
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
esac

exit $?
