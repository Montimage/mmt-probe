#!/bin/bash

#this script keeps alive an app
#Stop when removing its pid file

if [ "$#" -lt "2" ]; then
  echo "Run an app forever"
  echo "Usage: $0 ident app_to_run [ app_parameters ]"
  exit 0
fi

#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

IDENT_FILE=$1
IDENT_DIR=$(dirname "${IDENT_FILE}")
#create a folder containing log files if need
if [ ! -d "$IDENT_DIR" ]; then
  mkdir -p $IDENT_DIR
fi


#remove the first parameter that is $IDENT_FILE
shift
PROGRAM=$@

LOG_FILE=${IDENT_FILE}.log
PID_FILE=${IDENT_FILE}.pid

#invalidate the Ctrl+C/TERM signals
trap 'echo "Ignore this signal"' SIGINT SIGTERM

function stop() {
   #send sigint to the program
   kill -INT $PID
   #stop mmt-probe by kill its children 
   #send INT signal to all children of $PID
   pkill -INT -P $PID
   
   #wait for the program exits
   $DIR/wait.sh $PID
   
   echo "Stoped $PROGRAM" | tee -a $LOG_FILE
}

echo $$ > $PID_FILE
PID=$$


INDEX=0


#run the program in background
(
while true
do
   INDEX=$((INDEX+1))
   echo "$INDEX Start '$PROGRAM'" | tee -a $LOG_FILE
   
   #run the app
   $PROGRAM >> $LOG_FILE 2>&1 &
   
   _PID=$!
   echo $_PID > $PID_FILE
   
   #monitor CPU and memory usage of the app
   # the monitor scripts will exit when $_PID process exits
   $DIR/mon.sh $_PID > ${IDENT_FILE}.$INDEX.mon
   
   #exit this loop if the PID_FILE does not exist
   if [ ! -f $PID_FILE ]; 
   then
      exit 0
   fi
   
   #avoid runing burst
   sleep 5
done
) &

#loop until the PID_FILE is removed
while [ -f $PID_FILE ];
do 
   PID=`cat $PID_FILE`
   sleep 5
done

#when we touch here, the PID_FILE has been removed
stop

#wait for the children
wait