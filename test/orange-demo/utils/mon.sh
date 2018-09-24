#!/bin/bash

#This script monitors the usage of CPU and memory of a process.
#It writes the results on screen

if [ "$#" -ne "1" ]; then
  echo "Monitor CPU and Memory usages of a running process"
  echo "Usage: $0 pid"
  exit 0
fi

#ID of the process to be monitored
PID=$1
#print out the command line that was used to run the process
echo "# "`ps --no-headers -o 'cmd' -p $PID`

#header
echo "# timestamp CPU Virt-Memory(KB) Resident-Memory(KB)"

#loop when the process is existing
while [ -n "$(ps -p $PID -o pid=)" ];
do
   echo -n `date '+%H:%M:%S'` " "
   ps --no-headers -o '%cpu,vsz,rss' -p $PID
   sleep 5
done