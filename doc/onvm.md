# 1. OpenNetVM

## Installation
```bash
sudo apt-get install libnuma-dev 

# Clone source code
git clone https://manhdung_nguyen@bitbucket.org/montimage/opennetvm.git; cd opennetvm
git submodule sync 
git submodule update --init

# Export environment variables
echo export ONVM_HOME=$(pwd) >> ~/.bashrc
cd dpdk; echo export RTE_SDK=$(pwd) >> ~/.bashrc
echo export RTE_TARGET=x86_64-native-linuxapp-gcc  >> ~/.bashrc
echo export ONVM_NUM_HUGEPAGES=1024 >> ~/.bashrc
source ~/.bashrc
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"

# Run DPDK HelloWorld example
cd dpdk/examples/helloworld; make
sudo ./build/helloworld -l 0,1 -n 1

# Compile OpenNetVM and NF examples
cd onvm; make; cd ..
cd examples; make; cd ..

# Bind DPDK port
cd dpdk; sudo python3 usertools/dpdk-devbind.py --status # show ports
sudo python3 usertools/dpdk-devbind.py --bind=igb_uio 0000:01:00.0 # bind DPDK interface 0000:01:00.0
sudo python3 usertools/dpdk-devbind.py --unbind 0000:01:00.0 # unbind DPDK interface 0000:01:00.0

# Run openNetVM
onvm/go.sh -k 1 -n 0xF8 -s stdout -m 0,1,2
```

# 2. Packet Generator
## Tool PktGen on openNetVM
```bash
sudo apt-get install libpcap-dev libreadline-dev

# Install Lua version 5.3.5
cd ~/
curl -R -O http://www.lua.org/ftp/lua-5.3.5.tar.gz             
tar -zxf lua-5.3.5.tar.gz
cd lua-5.3.5
make linux test
sudo make install

# Build
cd tools/Pktgen/pktgen-dpdk/
make

# Run PktGen with only 1 port
./run-pktgen.sh 1

> start all # start sending packets to all ports (maximum 2 ports)
> start 0 # start sending packets to port 0
> stp # stop sending packets
> quit
```

## mmt-dpdk-replay
```bash
# Download DPDK version 17.11.4
wget http://static.dpdk.org/rel/dpdk-17.11.4.tar.gz 
tar -xvzf dpdk-17.11.4.tar.gz; cd dpdk-17.11.4.tar.gz

# Compile DPDK
source usertools/dpdk-setup.sh
# - Option: 14 - x86_64-native-linuxapp-gcc
# - Option: 30 - Remove IGB UIO module
# - Option: 21 - Setup hugepage mappings for NUMA systems
# Number of pages for node0: 20480 // 20Gb (server montimage 235)
# Number of pages for node1: 20480

# Test with helloworld example
cd examples/helloworld/; make
sudo ./build/app/helloworld -l 0-3 -n 3

# Set important environment variables
export RTE_SDK="/home/server10g/dung/dpdk-stable-17.11.4"
export RTE_TARGET=build

# Compile mmt-dpdk-liveplay-pcap
git clone https://manhdung_nguyen@bitbucket.org/montimage/mmt-dpdk-replay.git; cd mmt-dpdk-replay
server10g@ubuntu:~/dung/mmt-dpdk-liveplay-pcap$ make

# Bind DPDK port 
~/dpdk-stable-17.11.4$ sudo python3 usertools/dpdk-devbind.py --status
~/dpdk-stable-17.11.4$ sudo python3 usertools/dpdk-devbind.py --bind=igb_uio 0000:82:00.0

# Unbind and bind DPDK port using script
./dpdk-unbind-all-i40e.sh
./dpdk-bind-all-i40e.sh

# Run the tool mmt-dpdk-liveplay-pcap to generate traffic by replaying pcap files ()
#	-t: number of times to duplicate a packets
#   -m: mbps. By default, packets are replayed with the throughput of pcap file. Set this parameter to replay packets with the expected throughput.
#   -i: output port id
#   -l: loop through the pcap file X times. Not use together with -p
server10g@ubuntu:~/dung/mmt-dpdk-liveplay-pcap$ sudo ./mmt-dpdk-liveplay-pcap -c 0x1 -- -i 0 -t 16 -f ~/pcap/bigFlows.pcap -m 10000 -l 20

```

## NF Pcap-replay
```bash
TODO
```

# 3. Test on powerfull servers
## Connect to servers
```bash
# To SSH to the internal network of Montimage with IP 192.168.0.193
ssh -i /Users/strongcourage/montimage/.ssh/id_rsa montimage@92.154.110.165

# SSH to server10g with IP .7
montimage@montimage-OptiPlex-7020:~$ ssh server10g@192.168.0.7

# SSH to montimage with IP .235
montimage@montimage-OptiPlex-7020:~$ ssh montimage@192.168.0.235
```

# 4. NFs
## NF Probe
```bash
# Clone and compile Probe
git clone https://manhdung_nguyen@bitbucket.org/montimage/mmt-probe.git onvm
cd onvm; git checkout onvm
sudo make ONVM compile

# Run Probe with the configuration file
# - on 1 core (-n 0: only 1 instance)
# - on multiple cores (-n 5: 6 instances)
sudo ./probe -c onvm.conf
```

## NF Firewall
```bash
# Run NF Firewall with ID 1 and the firewall rule onvm.json
cd openNetVm/examples; make firewall
./start_nf.sh firewall 1 -d 2 -f firewall/onvm.json -b
```

## NF Load Balancer
```bash
TODO
```

## NF Scaling using Advanced Rings
```bash
./start_nf.sh scaling_example 1 -d 2 -n 2 -a
```

# NFs in Docker
```bash
TODO
```