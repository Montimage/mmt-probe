#!/bin/bash
apt-get update && apt-get install -y git cmake build-essential vim supervisor libpcre3-dev pkg-config libavl-dev libev-dev libprotobuf-c-dev protobuf-c-compiler libssh-dev libssl-dev swig python-dev

# add netconf user
adduser --system netconf && \
echo "netconf:netconf" | chpasswd

# generate ssh keys for netconf user
mkdir -p /home/netconf/.ssh && \
ssh-keygen -A && \
ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys

# use /opt/dev as working directory
mkdir /opt/dev

# libyang
cd /opt/dev && \
git clone https://github.com/CESNET/libyang.git && \
cd libyang && mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
make -j2 && \
make install && \
ldconfig

# sysrepo
cd /opt/dev && \
git clone https://github.com/sysrepo/sysrepo.git && \
cd sysrepo && mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo .. && \
make -j2 && \
make install && \
ldconfig


# libssh
cd /opt/dev && \
git clone http://git.libssh.org/projects/libssh.git && \
cd libssh && mkdir build && cd build && \
cmake .. && \
make -j2 && \
make install && \
ldconfig


# libnetconf2
cd /opt/dev && \
git clone https://github.com/CESNET/libnetconf2.git && \
cd libnetconf2 && mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
make -j2 && \
make install && \
ldconfig

# keystore
cd /opt/dev && \
git clone https://github.com/CESNET/Netopeer2.git && \
cd Netopeer2 && \
cd keystored && mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
make -j2 && \
make install && \
ldconfig

# netopeer2
cd /opt/dev && \
cd Netopeer2/server && mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
make -j2 && \
make install && \
cd ../../cli && mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
make -j2 && \
make install
