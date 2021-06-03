# OpenNetVM

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

## Tool PktGen
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

## NF Pcap-replay
```bash
TODO
```

## NF Probe
```bash
# Clone and compile Probe
git clone https://manhdung_nguyen@bitbucket.org/montimage/mmt-probe.git onvm
cd onvm; git checkout onvm
sudo make ONVM compile

# Run Probe with a specific config file
sudo ./probe -c onvm.conf
```

## NF Firewall
```bash
# Run NF Firewall with ID 1 and the firewall rule onvm.json
cd openNetVm/examples; make firewall
./start_nf.sh firewall 1 -d 2 -f firewall/onvm.json -b
```

## NF Load Balancer

## NFs in Docker