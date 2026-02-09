#!/bin/bash -x

if [ "$EUID" -ne 0 ]
	then echo "Please run this script under root user"
	exit
fi

# exit immediately when having error
set -e

# the temp directory to contain sources to be installed
TMP_DIR=$(mktemp -d -t mmt-probe-installation-XXXXXXXXXX)
# do not forget to remove the temp dir when exit
trap "rm -rf $TMP_DIR" EXIT

cd $TMP_DIR

# number of CPU cores
CPU=$(getconf _NPROCESSORS_ONLN)

# install libraries 
apt-get update && apt-get install -y \
	git cmake gcc g++ cpp\
	libconfuse-dev libpcap-dev libxml2-dev\
	curl

gcc -v

# install hiredis library
cd $TMP_DIR
git clone https://github.com/redis/hiredis.git hiredis
cd hiredis
git checkout v1.0.2 #just to ensure the compability
make -j $CPU
make install
ldconfig

# install librdkafka (C/C++ kafka client library)
cd $TMP_DIR
apt-get install -y libsasl2-dev libssl-dev
git clone https://github.com/edenhill/librdkafka.git librdkafka
cd librdkafka
git checkout v1.8.2 #just to ensure the compability
./configure
make -j $CPU
make install
ldconfig

# install libmongo
cd $TMP_DIR
apt-get install -y pkg-config libssl-dev libsasl2-dev
# use fixed version just to ensure the compability 
curl -Lk --output mongo-c.tar.gz https://github.com/mongodb/mongo-c-driver/releases/download/1.9.5/mongo-c-driver-1.9.5.tar.gz
tar xzf mongo-c.tar.gz
cd mongo-c-driver-1.9.5 #this folder name is fixed inside the mongo-c.tar.gz
./configure --disable-automatic-init-and-cleanup
make -j $CPU
make install
ldconfig


# install mmt-dpi
cd $TMP_DIR
git clone https://github.com/montimage/mmt-dpi mmt-dpi
cd mmt-dpi/sdk
make -j $CPU
make install
ldconfig
make deb

# install mmt-security
cd $TMP_DIR
apt-get install libxml2-dev libpcap-dev libconfuse-dev
git clone https://github.com/Montimage/mmt-security.git mmt-security
cd mmt-security
make clean-all
make -j1 #only one thread here to wait for the gneration of mmt-dpi.h
make install
ldconfig
make deb


# install mmt-probe
cd $TMP_DIR
git clone https://github.com/montimage/mmt-probe mmt-probe
cd mmt-probe
MODULES="KAFKA_MODULE MONGODB_MODULE PCAP_DUMP_MODULE QOS_MODULE REDIS_MODULE SECURITY_MODULE SOCKET_MODULE LTE_MODULE"
make -j $CPU $MODULES compile
make $MODULES deb
make $MODULES install
ls -lrat .
