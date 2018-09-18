#!/bin/bash

#This function needs 2 parameters:
# 1. Folder to mount
# 2. Folder size
function mountRAM {
  FOLDER=$1
  SIZE=$2
  if mountpoint $FOLDER > /dev/null ; then
    echo ""
  else
    sudo mount -t tmpfs -o size=$SIZE tmpfs $FOLDER
  fi  
}

#mount data folder to ramdisk to increase read/write performance
#report folder
mountRAM "/opt/mmt/probe/result/report/online" 5G 
#reports for behaviour
mountRAM "/opt/mmt/probe/result/behaviour/online" 5G 
#pcap files
mountRAM "/opt/mmt/probe/pcap" 50G 