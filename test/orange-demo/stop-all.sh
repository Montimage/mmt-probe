#!/bin/bash

# This script kills all processes used by MMT

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

killall -9 forever.sh
killall probe
killall node
killall mongod
killall sleep