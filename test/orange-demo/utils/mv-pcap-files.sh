#!/bin/bash

#this script will periodically:
# - move pcap files from a src folder to a dst folder.
# - keep at least x pcap files in src folder
# - maintain total size of dst folder by removing the oldest pcap file

if [[ "$#" -ne "3" ]]; then
  echo "Usage: $0 source dest nb_retain"
  exit 1
fi

#byte limit for storaging pcaps: 600GB
LIMIT_SIZE=600000000000

SRC_FOLDER=$1
DST_FOLDER=$2
RETAIN=$3

#check if src folder exists
if [  ! -d $SRC_FOLDER ];
then
   echo "Source folder $SRC_FOLDER does not exist"
   exit 0
fi

#create the dst folder if need
if [  ! -d $DST_FOLDER ];
then
   mkdir -p $DST_FOLDER
fi

#get the oldest file from a folder
#this function has one input: folder to get the oldest file
function getOldestPcap {
  FOLDER=$1
  oldest=`ls -1t $FOLDER | grep pcap$ | tail -1`
  echo $FOLDER/$oldest
}


function maintainSize {
  #loop until the size of $DST_FOLDER <= $LIMIT_SIZE
  while true
  do
    SIZE=$(du -b $DST_FOLDER | cut -f1)
    if [ $SIZE -le $LIMIT_SIZE ]
      break
    then
      OLDEST=`getOldestPcap $DST_FOLDER`
      echo ">>>>> $SIZE >= $LIMIT_SIZE rm $OLDEST"
      rm $OLDEST
    fi
  done
}


#loop until having pcap files to move
while true
do
    count=`ls -la $SRC_FOLDER | grep pcap$ | wc -l`
    if [ $count -le $RETAIN ]
    then
      break
    else
      (( i++ ))
      
      #move the oldest file from SRC_FOLDER to DST_FOLDER
      OLDEST=`getOldestPcap $SRC_FOLDER`
      FILESIZE=$(du -h "$OLDEST" | cut -f1)
      echo $i `date +'%H:%M:%S'` $OLDEST $FILESIZE
      mv $OLDEST $DST_FOLDER
      
      #remove the oldest file from $DST_FOLDER if need
      maintainSize
    fi  
done