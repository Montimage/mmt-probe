#!/bin/bash

if [ "$#" -lt "1" ]; then
  echo "Wait for a process"
  echo "Usage: $0 pid"
  exit 0
fi

#invalidate the Ctrl+C/TERM signals
trap 'echo "$$ ignores this signal"' SIGINT SIGTERM SIGUSR1 SIGUSR2

PID=$1

while [ -e /proc/$PID ]; 
do 
   #wait $PID;
   #wait $PID will not work if $PID is not a child of this process
   
   sleep 1
done
