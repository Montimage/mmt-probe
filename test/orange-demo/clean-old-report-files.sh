#!/bin/bash

function removeAll {
  FOLDER=$1
  for i in $FOLDER/*;
  do
    sudo rm -rf $i;
  done
}

#removeAll /opt/mmt/probe/pcap
removeAll /opt/mmt/probe/result/report/online
removeAll /opt/mmt/probe/result/behaviour/online