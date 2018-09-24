#!/bin/bash -x

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi


#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
FOREVER="$DIR/utils/forever.sh"
MMT_DIR=/home/mmt/mmt

#file containing pid of this script process
PID_FILE=$DIR/mmt.pid


#current time
NOW=`date '+%Y-%m-%d_%H-%M-%S'`
#folder we put execution logs of the processes (ba, bw, probe, operator, mongodb)
LOG_IDENT="/tmp/"

#create a folder containing log files if need
if [ ! -d "$LOG_IDENT" ]; then
  mkdir -p $LOG_IDENT
fi


#Stop a process and wait for until finish
function stop(){ 
   $DIR/utils/stop.sh $1
}


( $FOREVER ${LOG_IDENT}/mongod sleep infinity )&

#store pid of the current process to a file so we can stop the process by using ./stop-mmt.sh
echo $$ > $PID_FILE

echo "Started MMT-Behaviour ..."


(
#loop until the PID_FILE is removed
while [ -f $PID_FILE ];
do 
   sleep 1
done

#when we touch here, the PID_FILE has been removed
stop ${LOG_IDENT}/mongod

echo "Bye"
) &

