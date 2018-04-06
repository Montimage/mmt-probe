#!/bin/sh -e

### BEGIN INIT INFO
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Start MMT-Probe
# Provides:          mmt-probe
### END INIT INFO

# Author: Montimage <contact@montimage.com>
# March 30, 2018

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin

DAEMON_FILE=/opt/mmt/probe/bin/probe

PID_FILE=/var/run/mmt-probe.pid
SERVICE_FILE=/etc/init.d/mmt-probe

NAME="MMT-Probe"

# Exit if the package is not installed or not executable
[ -x "$DAEMON_FILE" ] || (echo "Cannot execute $DAEMON_FILE" >&2; exit 1) || exit 0

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

# Function that starts the daemon/service
do_start()
{
	#check if mmt-probe is running
	start-stop-daemon        \
		--start              \
		--oknodo             \
		--background         \
		--pidfile $PID_FILE  \
		--make-pidfile       \
		--exec $DAEMON_FILE
	return $?
}

# Function that stops the daemon/service
do_stop()
{
	start-stop-daemon        \
		--stop               \
		--oknodo             \
		--quiet              \
		--remove-pidfile     \
		--signal INT         \
		--retry  30          \
		--pidfile $PID_FILE
	return $?
}

case "$1" in
  start)
        log_daemon_msg "Starting $NAME"
        do_start
        case "$?" in
                0) log_end_msg 0 ;;
                *) log_end_msg 1 ;;
        esac
        ;;
        
  stop)
        log_daemon_msg "Stopping $NAME"
        do_stop
        case "$?" in
                0|1) log_end_msg 0 ;;
                2)   log_end_msg 1 ;;
        esac
        ;;
        
  status)
        status_of_proc -p "$PID_FILE" "$DAEMON_FILE" "$NAME"  && exit 0 || exit $?
        ;;
        
  restart)
        log_daemon_msg "Restarting $NAME"
        do_stop
        case "$?" in
          0)
                do_start
                case "$?" in
                        0) log_end_msg 0 ;;
                        *) log_end_msg 1 ;;
                esac
                ;;
          *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
        
  *)
        echo "Usage: $SERVICE_FILE {start|stop|status|restart}"  >&2
        exit 3
        ;;
esac
