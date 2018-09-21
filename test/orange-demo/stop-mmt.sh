#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
#file containing pid of this script process
PID_FILE=$DIR/mmt.pid



#if pid file is existing => send an exit signal to its process
if [[  -f $PID_FILE ]]; then
   PID=`cat $PID_FILE`
   
   #send USR1 signal to mmt process
   kill -SIGUSR1 $PID
   
   #as $PID is not a child of this proc, so we cannot use "wait $PID"
   #wait $PID
   while [ -e /proc/$PID ]; do sleep 1; done
fi

exit
sudo killall -SIGUSR2 forever.sh 2>/dev/null
sudo killall probe      2>/dev/null
sudo killall ba         2>/dev/null
sudo killall node       2>/dev/null
sudo killall mongod     2>/dev/null