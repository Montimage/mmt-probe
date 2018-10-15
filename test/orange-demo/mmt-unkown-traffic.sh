#!/bin/bash

#This script starts MMT-Probe to dump unknown traffic to pcap files
# and MMT-Operator to see the result 

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi


#this folder storages pcap files
PCAP_STORAGE_FOLDER="/data/pcap"


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
LOG_IDENT="/data/log/log-probe-unknown-traffic/$NOW/"

#create a folder containing log files if need
if [ ! -d "$LOG_IDENT" ]; then
  mkdir -p $LOG_IDENT
fi


function mmt(){
#This script will start mmt-behaviour analisys.
#Basically, it will run:
#0. MongoDB
#1. MMT-Operator
#2. MMT-Probe


#Stop a process and wait for until finish
#Stop a process and wait for until finish
function stop(){ 
   $DIR/utils/stop.sh $1
}

#invalidate the Ctrl+C/TERM signals
trap 'echo "Ignore this signal"' SIGINT SIGTERM


#0. MongoDB
DB_PATH=/data/database/mmt-probe-unknown-traffic
mkdir -p $DB_PATH
#stop the current mongodb
sudo service mongod stop
sudo kill -SIGINT mongod 2> /dev/null

(  $FOREVER ${LOG_IDENT}mongodb mongod --dbpath $DB_PATH --quiet --wiredTigerCacheSizeGB 20 )&

sleep 10

#1. MMT-Operator
cd $MMT_DIR/mmt-operator/www
(  $FOREVER ${LOG_IDENT}operator bin/www --config=$DIR/conf/operator-unknown-traffic.json )&


#2. MMT-Probe
cd $MMT_DIR/mmt-probe
( $FOREVER ${LOG_IDENT}probe ./probe -c $DIR/conf/probe.conf -Xdump-pcap.enable=true )&


#3. Sync pcap files from a RAM folder to a disk folder
# to increase the performance, Probe does not dump directly packets to disk, but to a RAM-mounted folder
# This script will sync by burst the pcap files from the RAM-folder to a disk-folder
#this folder is mounted to RAM and receives directly packets from Probe
PCAP_RAM_FOLDER="/opt/mmt/probe/pcap"


#loop until the PID_FILE is removed
while [ -f $PID_FILE ];
do 
   $DIR/utils/mv-pcap-files.sh $PCAP_RAM_FOLDER $PCAP_STORAGE_FOLDER 16
   sleep 1
done

echo "Stop MMT"

#when we touch here, the PID_FILE has been removed
stop ${LOG_IDENT}/probe
stop ${LOG_IDENT}/operator
stop ${LOG_IDENT}/mongodb
wait

#move the rest pcap files to disk
for i in $PCAP_RAM_FOLDER/* ;
do
   mv $i $PCAP_STORAGE_FOLDER &
done
wait



echo "Bye"

}


echo "Start MMT ..."
mmt > ${LOG_IDENT}script.log 2>&1 &

#store pid of the current process to a file so we can stop the process by using ./stop-mmt.sh
echo $! > $PID_FILE
