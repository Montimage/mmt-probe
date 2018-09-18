#!/bin/bash

#this script keeps alive an app
#Stop when pressing Ctrl+C

if [ "$#" -lt "2" ]; then
  echo "Run an app forever"
  echo "Usage: $0 ident app_to_run [ app_parameters ]"
  exit 0
fi

#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

LOG_FILE=$1
LOG_DIR=$(dirname "${LOG_FILE}")
#create a folder containing log files if need
if [ ! -d "$LOG_DIR" ]; then
  mkdir -p $LOG_DIR
fi


#remove the first parameter that is $LOG_FILE
shift
PROGRAM=$@


#intercept Ctrl+C
trap ctrl_c INT
function ctrl_c() {
   echo "<- Stop $PROGRAM"
   kill -SIGINT $PID 2> /dev/null
   
   wait $PID
   echo "<-- Stoped $PROGRAM"
   exit 0
}

INDEX=0

LOG_FILE=${LOG_FILE}_`date '+%Y-%m-%d_%H-%M-%S'`

while true
do
   INDEX=$((INDEX+1))
   echo "-> $INDEX Start '$PROGRAM'" | tee -a ${LOG_FILE}.log
   
   #run the app
   ( $PROGRAM >> ${LOG_FILE}.log 2>&1 ) &
   
   
   #monitor CPU and memory usage of the app
   PID=$!
   $DIR/mon.sh $PID > ${LOG_FILE}.$INDEX.mon
   
   #avoid runing burst
   sleep 1
done

