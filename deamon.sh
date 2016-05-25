#!/bin/bash

#mmt probe service for runing online

MODE=runing_mode
PROBE=/opt/mmt/probe/bin/probe_$MODE
CONFIG=/opt/mmt/probe/conf/$MODE.conf
LOGFILE=/opt/mmt/probe/log/$MODE/deamon_$(date +%F).log

if [ $MODE = "running_mode" ]; then
    echo "Please contact montimage"
    exit 0
fi 


#check if file exist
if [ ! -e "$PROBE" ]; then
    echo "$PROBE does not exist"
    exit 0
fi
if [ ! -e "$CONFIG" ]; then
    echo "$CONFIG does not exist"
    exit 0
fi

# Start the service
start() {
    if [ "$MODE" = "online" ]; then
        (while true; do 
            $PROBE -c $CONFIG &>> $LOGFILE
            sleep 5
        done) &
    else
        $PROBE -c $CONFIG &>> $LOGFILE &
    fi
    
    echo " started service"
    echo
}

# stop the service
stop() {
    #kill the real program
    pkill -f $PROBE
    #kill the deamon
    pkill -f "probe_${MODE}_d"
    
    echo " stopped service"
    echo
}

# restart the service 
restart () {
    stop 
    start
}


status (){
    RESULT=`pidof ${PROBE}`

    if [ "${RESULT:-null}" = null ]; then
        echo " service is not running"
    else
        echo " service is running"
    fi
    echo
}

### main logic ###
case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  status)
        status
        ;;
  restart)
        restart
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart|status}"
        exit 1
esac
exit 0
