#!/bin/bash

# This script starts MMT toolchain for behaviour analysing.

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

if [ -f $PID_FILE ];
then 
   echo "Another instance of MMT is running. Stop it first"
   exit 0
fi

#current time
NOW=`date '+%Y-%m-%d_%H-%M-%S'`
#folder we put execution logs of the processes (ba, bw, probe, operator, mongodb)
LOG_IDENT="/data/log/log-behaviour/$NOW/"

#create a folder containing log files if need
if [ ! -d "$LOG_IDENT" ]; then
  mkdir -p $LOG_IDENT
fi


function mmtBehaviour(){
#This script will start mmt-behaviour analisys.
#Basically, it will run:
#0. MongoDB
#1. MMT-Bandwidth
#2. MMT-Behaviour
#3. MMT-Operator
#4. MMT-Probe


#Stop a process and wait for until finish
function stop(){ 
   $DIR/utils/stop.sh $1
}

#invalidate the Ctrl+C/TERM signals
trap 'echo "Ignore this signal"' SIGINT SIGTERM


#0. MongoDB
DB_PATH=/data/database/mmt-behaviour
mkdir -p ${DB_PATH}-operator
mkdir -p ${DB_PATH}-bandwidth

#stop the current mongodb
sudo service mongod stop
sudo kill -SIGINT mongod 2> /dev/null

#MongoDB for Operator
(  $FOREVER ${LOG_IDENT}mongodb mongod --dbpath ${DB_PATH}-operator --quiet --wiredTigerCacheSizeGB 20 )&

(  $FOREVER ${LOG_IDENT}mongodb-bw mongod --dbpath ${DB_PATH}-bandwidth --port 27018 --quiet --wiredTigerCacheSizeGB 20 )&

sleep 10

#1. MMT-Bandwidth
cd $MMT_DIR/mmt-bandwidth
(  $FOREVER ${LOG_IDENT}bw node app.js )&

#2. MMT-Behaviour
cd $MMT_DIR/mmt-behaviour
(  $FOREVER ${LOG_IDENT}ba ./ba -c $DIR/conf/ba.conf )&

#3. MMT-Operator
cd $MMT_DIR/mmt-operator/www
(  $FOREVER ${LOG_IDENT}operator bin/www --config=$DIR/conf/operator-behaviour.json )&


sleep 2
#4. MMT-Probe
cd $MMT_DIR/mmt-probe
( $FOREVER ${LOG_IDENT}probe ./probe -c $DIR/conf/probe.conf -Xbehaviour.enable=true )&


#loop until the PID_FILE is removed
while [ -f $PID_FILE ];
do 
   sleep 5
done

echo "Stop MMT-Behaviour"

#when we touch here, the PID_FILE has been removed
stop ${LOG_IDENT}/probe
stop ${LOG_IDENT}/ba
stop ${LOG_IDENT}/bw
stop ${LOG_IDENT}/operator
stop ${LOG_IDENT}/mongodb
stop ${LOG_IDENT}/mongodb-bw

wait

echo "Bye"

}


echo "Start MMT-Behaviour ..."
mmtBehaviour > ${LOG_IDENT}script.log 2>&1 &

#store pid of the current process to a file so we can stop the process by using ./stop-mmt.sh
echo $! > $PID_FILE
