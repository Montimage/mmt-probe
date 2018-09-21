#!/bin/bash

if [[ "$#" != "2" ]]; then
   echo "Usage: $0 folder_to_mount allocate_size"
   echo "For example: sudo $0 /tmp/_ram 1G"
   exit
fi

#This function needs 2 parameters:
# 1. Folder to mount
# 2. Folder size
function mountRAM {
  FOLDER=$1
  SIZE=$2
  if mountpoint $FOLDER > /dev/null ; then
    echo " $FOLDER already mounted"
  else
    sudo mount -t tmpfs -o size=$SIZE tmpfs $FOLDER
    echo " $FOLDER has been mounted to $SIZE of RAM"
  fi
}

mountRAM $1 $2