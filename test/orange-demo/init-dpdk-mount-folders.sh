#!/bin/bash

# This script must be run only once before starting MMT
#
# It peforms 3 taks:
#1. Stop unnecessary system services
#2. Bind NIC cards to DPDK
#3. Mount output folders of MMT to RAM to increase writing/reading performance

if [[ -z "$RTE_SDK" ]]; then
   echo "RTE_SDK is not defined."
   
   #if this script was run under root
   if [ "$(id -u)" == "0" ]; then
      echo "You may want to use 'sudo -E'"
   fi
   exit
fi

#who is using this?
sudo service php7.0-fpm   stop
#sudo service postgresql  stop
sudo service redis-server stop
sudo service mongod       stop
sudo service snapd        stop
sudo service irqbalance   stop

export IRQBALANCE_BANNED_CPUS=0x55555555555
sudo irqbalance

#get the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"



echo "--> Load DPDK driver"
cd $RTE_SDK/$RTE_TARGET/kmod/

sudo modprobe uio
sudo insmod ./igb_uio.ko



echo "--> Bind DPDK driver"
cd $RTE_SDK/usertools
#0000:01:00.0 'Ethernet Controller X710 for 10GbE SFP+' if=eno1 drv=i40e unused= *Active*
#0000:01:00.1 'Ethernet Controller X710 for 10GbE SFP+' if=eno2 drv=i40e unused= *Active*
#0000:01:00.2 'Ethernet Controller X710 for 10GbE SFP+' if=eno3 drv=i40e unused= 
#0000:01:00.3 'Ethernet Controller X710 for 10GbE SFP+' if=eno4 drv=i40e unused= 
#0000:03:00.0 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0 drv=ixgbe unused= *Active*


sudo ./dpdk-devbind.py --bind=igb_uio 03:00.0

sudo ./dpdk-devbind.py --bind=igb_uio 01:00.0
sudo ./dpdk-devbind.py --bind=igb_uio 01:00.1
sudo ./dpdk-devbind.py --bind=igb_uio 01:00.2
sudo ./dpdk-devbind.py --bind=igb_uio 01:00.3

#sudo ./dpdk-devbind.py --status

#echo "--> Setup 40GB hugepage"
#echo 20000 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
#it is not possible to reserve the hugepages 1G after the system has booted
#echo 3     | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages



echo "--> Mount mmt folders to RAM"


mountRAM=$DIR/utils/mount-folder-to-ram.sh

#mount data folder to ramdisk to increase read/write performance
#report folder
$mountRAM "/opt/mmt/probe/result/report/online" 5G 
#reports for behaviour
$mountRAM "/opt/mmt/probe/result/behaviour/online" 5G 
#pcap files
$mountRAM "/opt/mmt/probe/pcap" 50G 

#create folder containing execution log
mkdir -p /data/log/operator/ 2>&1