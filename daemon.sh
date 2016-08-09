#!/bin/sh
### BEGIN INIT INFO
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Start MMT-Probe
### END INIT INFO

# Author: Montimage <contact@montimage.com>
# 09 August 2016

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin


#this will be changed when installing by Makefile
MODE=runing_mode

NAME=mmt-probe
DAEMON=/opt/mmt/probe/bin/probe
DAEMON_ARGS=/opt/mmt/probe/conf/$MODE.conf
LOGFILE=/opt/mmt/probe/log/$MODE/daemon_$(date +%F).log

PIDFILE=/var/run/mmt-probe-$MODE.pid
SCRIPTNAME=/etc/init.d/probe_$MODE_d
DESC="MMT-Probe"

if [ "$MODE" = "running_mode" ]; then
    echo "Please contact contact@montimage.com"
    exit 0
fi 



# Exit if the package is not installed
[ -x "$DAEMON" ]      || (echo "Cannot find $DAEMON"     ; exit 1) || exit 0
[ -e "$DAEMON_ARGS" ] || (echo "Cannot find $DAEMON_ARGS"; exit 1) || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
        # Return
        #   0 if daemon has been started
        #   1 if daemon was already running
        #   2 if daemon could not be started
        start-stop-daemon --start --quiet --pidfile $PIDFILE --make-pidfile --name $NAME --startas /bin/bash --test > /dev/null \
                || return 1
        start-stop-daemon --start --background --quiet --pidfile $PIDFILE --make-pidfile --name $NAME \
                            --startas /bin/bash -- -c "exec $DAEMON -c $DAEMON_ARGS >> $LOGFILE 2>&1" \
                || return 2
}

#
# Function that stops the daemon/service
#
do_stop()
{
        # Return
        #   0 if daemon has been stopped
        #   1 if daemon was already stopped
        #   2 if daemon could not be stopped
        #   other if a failure occurred
        start-stop-daemon --stop --signal KILL  --quiet --retry=INT/31/KILL/5 --pidfile $PIDFILE --name $NAME
        RETVAL="$?"
        [ "$RETVAL" = 2 ] && return 2

        # Wait for children to finish too if this is a daemon that forks
        # and if the daemon is only ever run from this initscript.
        # If the above conditions are not satisfied then add some other code
        # that waits for the process to drop all resources that could be
        # needed by services started subsequently.  A last resort is to
        # sleep for some time.
        start-stop-daemon --stop --quiet --oknodo  --retry=INT/31/KILL/5 --exec $DAEMON
        [ "$?" = 2 ] && return 2

        # don't forget to delete their pidfiles when they exit.
        rm -f $PIDFILE
        return "$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
        #
        # If the daemon can reload its configuration without
        # restarting (for example, when it is sent a SIGHUP),
        # then implement that here.
        #
        start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name $NAME
        return 0
}
case "$1" in
  start)
        echo "Start MMT-Probe at $(date +%c)" >> $LOGFILE
        log_daemon_msg "Starting " "$DESC"
        do_start
        case "$?" in
                0|1) log_end_msg 0 ;;
                2)   log_end_msg 1 ;;
        esac
        ;;
  stop)
        echo "Stop MMT-Probe at $(date +%c)" >> $LOGFILE
        log_daemon_msg "Stopping " "$DESC"
        do_stop
        case "$?" in
                0|1) log_end_msg 0 ;;
                2)   log_end_msg 1 ;;
        esac
        ;;
  status)
        status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
        ;;
  #reload|force-reload)
        #
        # If do_reload() is not implemented then leave this commented out
        # and leave 'force-reload' as an alias for 'restart'.
        #
        #log_daemon_msg "Reloading $DESC" "$NAME"
        #do_reload
        #log_end_msg $?
        #;;
  restart|force-reload)
        #
        # If the "reload" option is implemented then remove the
        # 'force-reload' alias
        #
        log_daemon_msg "Restarting " "$DESC"
        do_stop
        case "$?" in
          0|1)
                do_start
                case "$?" in
                        0) log_end_msg 0 ;;
                        1) log_end_msg 1 ;; # Old process is still running
                        *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
          *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
  *)
        echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}"  >&2
        exit 3
        ;;
esac
