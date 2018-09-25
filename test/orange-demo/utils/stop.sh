#!/bin/bash

if [ "$#" -lt "1" ]; then
  echo "Stop an app being run by forever.sh"
  echo "Usage: $0 ident"
  exit 0
fi

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

#file containing pid of this script process
PID_FILE=$1

if [[ $PID_FILE != *.pid ]] ;
then
   PID_FILE=${PID_FILE}.pid
fi



#if pid file is existing => send an exit signal to its process
if [[  -f $PID_FILE ]]; then
   PID=`cat $PID_FILE`
   
   echo "Stop "`ps --no-headers -o 'cmd' -p $PID`
   
   rm $PID_FILE
   #as $PID is not a child of this proc, so we cannot use "wait $PID"
   #wait $PID
   while [ -e /proc/$PID ]; do sleep 1; done
else
   #echo to stderr
   (>&2 echo "App is not running")
fi