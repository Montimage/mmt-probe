#!/bin/bash -x

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi


#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
FOREVER=$DIR/utils/forever.sh
MMT_DIR=/home/mmt/mmt

#file containing pid of this script process
PID_FILE=$DIR/mmt.pid

#current time
NOW=`date '+%Y-%m-%d_%H-%M-%S'`
#folder we put execution logs of the processes (ba, bw, probe, operator, mongodb)
LOG_IDENT="$DIR/log-behaviour/$NOW/"

#create a folder containing log files if need
if [ ! -d "$LOG_IDENT" ]; then
  mkdir -p $LOG_IDENT
fi


function _wait(){ 
   while [ -e /proc/$1 ]; do sleep 1; done
}

function mmtBehaviour(){
#This script will start mmt-behaviour analisys.
#Basically, it will run:
#0. MongoDB
#1. MMT-Bandwidth
#2. MMT-Behaviour
#3. MMT-Operator
#4. MMT-Probe


#Mount reports folder to RAM to incrase performance
# $DIR/mount-folder-to-ram.sh
#Use DPDK to capture packet
# $DIR/dpdk-bind-nic.sh

#store pid of mongoDB, Behaivour, bandwidth and operator
PID_MONGODB=0
PID_BA=0
PID_BW=0
PID_OPERATOR=0
PID_PROBE=0

#Stop a process and wait for until finish
function stop(){ 
   PID=$1
   #echo "Stop "`ps --no-headers -o 'cmd' -p $PID`
   kill -SIGUSR2 $PID #2> /dev/null
   
   #loop when the process is existing
   wait $PID
}

#invalidate the Ctrl+C/TERM signals
trap 'echo "Ignore this signal"' SIGINT SIGTERM

#stop when receiving USR1 signal
trap _stop SIGUSR1
function _stop() {
   echo ""
   
   stop $PID_PROBE
   stop $PID_BW
   stop $PID_BA
   stop $PID_OPERATOR
   stop $PID_MONGODB
   
   rm $PID_FILE
}


#0. MongoDB
DB_PATH=/data/database/mmt-behaviour
mkdir -p $DB_PATH
#stop the current mongodb
sudo service mongod stop
sudo kill -SIGINT mongod 2> /dev/null

(  $FOREVER ${LOG_IDENT}mongodb mongod --dbpath $DB_PATH --syslog --wiredTigerCacheSizeGB 20 )&
PID_MONGODB=$!

sleep 10

#1. MMT-Bandwidth
cd $MMT_DIR/mmt-bandwidth
(  $FOREVER ${LOG_IDENT}bw node app.js )&
PID_BW=$!

#2. MMT-Behaviour
cd $MMT_DIR/mmt-behaviour
(  $FOREVER ${LOG_IDENT}ba ./ba -c $DIR/conf/ba.conf )&
PID_BA=$!

#3. MMT-Operator
cd $MMT_DIR/mmt-operator/www
(  $FOREVER ${LOG_IDENT}operator bin/www --config=$DIR/conf/operator.json )&
PID_OPERATOR=$!


sleep 2
#4. MMT-Probe
cd $MMT_DIR/mmt-probe
( $FOREVER ${LOG_IDENT}probe ./probe -c $DIR/conf/probe.conf -Xbehaviour.enable=true )&
PID_PROBE=$!

#wait all sub-processes finish
wait
}


echo "Start MMT-Behaviour ..."
mmtBehaviour > ${LOG_IDENT}script.log 2>&1 &

#store pid of the current process to a file so we can stop the process by using ./stop-mmt.sh
echo $! > $PID_FILE