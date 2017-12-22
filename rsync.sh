#!/bin/bash

echo "Compiling `pwd` ... "

#rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p 2222" -rca ./* .git mmt@localhost:/home/mmt/mmt-probe
#ssh -p 2222 mmt@localhost "cd mmt-probe; make clean PCAP=1; make PCAP=1 && ./copy probe"

#exit 0
#TARGET=/home/mmt/mmt-probe
#USER=mmt
#IP=localhost
#PORT=2222

#TARGET=/home/server10g/huunghia/mmt-probe
#USER=server10g
#IP=192.168.0.7
#PORT=22

#USER=montimage
#IP=192.168.0.194

#TARGET=/home/server10ga/huunghia/mmt-probe
#USER=root
#IP=192.168.0.36

IP=localhost
TARGET=/home/mmt/mmt-probe
USER=mmt
PORT=2222

rsync -e "ssh -i /Users/nhnghia/.ssh/id_rsa -p $PORT" -rca .git ./* $USER@$IP:$TARGET

DEBUG="DEBUG=1 VALGRIND=1 VERBOSE=1 PCAP=1 SECURITY_MODULE=1"

#EXPORT="export RTE_SDK=/home/server10g/huunghia/dpdk-stable-16.11.1/; export RTE_TARGET=x86_64-native-linuxapp-gcc"
#RUN="$EXPORT;  make clean DPDK=1; make DPDK=1 -j2 && cp ./build/probe ./"

RUN="make clean PCAP=1; make PCAP=1 DEBUG=1"
#RUN="make clean PCAP=1; make PCAP=1 $DEBUG -j5 && cp probe ../hn"

RUN="gcc -g -O0 -o probe src/lib/configure.c src/lib/version.c src/main.c -lconfuse && valgrind --leak-check=full --show-leak-kinds=all ./probe -c mmt_online.conf"
RUN="make clean $DEBUG; make $DEBUG"

ssh -p $PORT $USER@$IP "cd $TARGET && $RUN"