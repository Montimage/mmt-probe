#!/bin/bash

# This script stops MMT

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

#file containing pid of this script process
PID_FILE=$DIR/mmt

$DIR/utils/stop.sh $PID_FILE