#!/bin/bash

[[ -z "$RTE_SDK" ]] && echo "RTE_SDK is not defined." && exit

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


sudo ./dpdk-devbind.py --bind=igb_uio 01:00.0
sudo ./dpdk-devbind.py --bind=igb_uio 01:00.1
sudo ./dpdk-devbind.py --bind=igb_uio 01:00.2
sudo ./dpdk-devbind.py --bind=igb_uio 01:00.3

sudo ./dpdk-devbind.py --status

#echo "--> Setup 40GB hugepage"
#echo 20000 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
#it is not possible to reserve the hugepages 1G after the system has booted
#echo 3     | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
echo "--> Done"