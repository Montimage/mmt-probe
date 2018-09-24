#!/bin/bash

#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
#file containing pid of this script process
PID_FILE=$DIR/mmt.pid



#if pid file is existing => send an exit signal to its process
if [[  -f $PID_FILE ]]; then
   PID=`cat $PID_FILE`
   pstree -pahn $PID

else
   echo "MMT is not running"
fi