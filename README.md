# MMT Probe

## Documentation

See [Wiki](https://bitbucket.org/montimage/mmt-probe/wiki)

## Getting Started

# Compile the key generator if need
    make keygen
    #./keygen
    
# Complile MMT-SDK and MMT-security
    MMT-probe requires MMT-SDK and MMT-security to be installed before hand

# Compile the probe
    #if need, remove old installation:
    #sudo make dist-clean
    
    #if in PCAP mode
    #To clean
    make clean PCAP=1
    #To compile
    make PCAP=1
    #Compile with DEBUG
    #make PCAP=1 DEBUG=1
    
    sudo make create PCAP=1
    
    #if in DPDK mode
    make clean DPDK=1
    #To compile
    make DPDK=1
    #Compile with DEBUG
    #make DPDK=1 DEBUG=1
    
    sudo make create DPDK=1
# Execute locally (DPDK):
    #CORE_MASK: hexadecimal bit mask (eg. AAAAAAAAAB)
    sudo ./build/probe -c CORE_MASK -- -c mmt_online.conf
# Execute locally:
    sudo ./probe -c mmt_online.conf
# Execute as service
    sudo service probe_online_d start
    #see status
    sudo service probe_offline_d status
    #stop the service if need
    sudo service probe_online_d stop
    #if need, change probe_online_d by probe_offline_d to run offline
    #if need, see the execution log at /opt/mmt/probe/log/online/
# If view data by mmt_operator
    #redis-server
    #goto mmt-operator folder
    #cd mmt-operator
    sudo npm start
    firefox localhost

# Simple probe:
    gcc -o simple_probe src/main.c -lmmt_core -ldl -lpcap
    #execute
    ./simple_probe <pcap file>

# This assumes that you have:

## MMT-SDK
    git clone git@bitbucket.org:montimage/mmt-sdk.git
    cd mmt-sdk/sdk
    make -j4
    sudo make install
    
## MMT-Security
    https://bitbucket.org/montimage/mmt-security
    
## MMT-Operator
    git clone git@bitbucket.org:montimage/mmt-operator.git
    cd mmt-operator
    npm install
