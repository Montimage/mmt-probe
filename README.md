# MMT Probe

## Documentation

See [Wiki](https://bitbucket.org/montimage/mmt-probe/wiki)

## Getting Started

# Compile the key generator if need
    make keygen
    #./keygen

# Complile MMT-SDK
    MMT-probe requires MMT-SDK to be installed before hand. See https://bitbucket.org/montimage/mmt-sdk/wiki/Compilation%20and%20Installation%20Instructions

# Compile the probe

```
    #if need, remove old installation:
    #sudo make dist-clean

    #if in PCAP mode
    #To clean
    make clean
    #To compile using PCAP to capture packets
    make
    #Compile with DEBUG
    #make DEBUG=1
    sudo make install
```

## Compile PROBE with TCP_PAYLOAD_DUMP option

Compile PROBE with TCP_PAYLOAD_DUMP option allows PROBE to dump the TCP payload with the tcp segmentation will be take into account

To compile the PROBE with this option, there are 2 dependencies need to be install (in order):

### Install libntoh

Libntoh is a library which provides a easy way to perform defragmentation and reassembly of IP/IPV6, TCP protocols

Download and install libntoh:

```
git clone https://YOUR_USER_NAME@bitbucket.org/montimage/libntoh.git
cd libntoh/src/
./build.sh
```

### Install MMT-REASSEMBLY

MMT-REASSEMBLY is a module (like an adapter) to integrate `libntoh` into `MMT-SDK`

Download and install MMT-REASSEMBLY

```
git clone https://YOUR_USER_NAME@bitbucket.org/montimage/mmt-reassembly.git
cd mmt-reassembly/sdk/
make -j4
sudo make install

```

### Compile PROBE

Now we can compile PROBE with option `TCP_PAYLOAD_DUMP=1`

```
make TCP_PAYLOAD_DUMP=1
```

### Test
After compiling PROBE with option TCP_PAYLOAD_DUMP=1, you can update the location where the tcp payload will be stored in the configuration file `mmt_probe.conf`:

```
condition_report tcp_payload_dump
{
    enable = 1
    condition = "TCP_PAYLOAD_DUMP"
    location = "files/"
    attributes = {"ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.src_port", "tcp.dest_port", "tcp.p_payload", "tcp.payload_len"}
    handlers   = {"NULL"  , "NULL"  , "NULL"    , "NULL"    , "NULL"        , "NULL"         , "NULL"         , "NULL"}
}
```

Test our PROBE by running the command:

```
./probe -c mmt_probe.conf -i eth0
```

### Packet capture using `PCAP` or `DPDK`

MMT-Probe supports either `PCAP` or `DPDK` to capture packets.
`PCAP` is selected if none of them are specified.
Use cannot use both `PCAP` and `DPDK` when compiling.

    #Use DPDK
    make DPDK=1
    #Use PCAP
    make #or make PCAP=1
    #Undefined:
    #make PCAP=1 DPDK=1

### Modules

#### Output bus:  `REDIS` or `KAFKA`

In addition to output reports to files, MMT-Probe can ouput to redis or kafka servers.
Contrary to the packet capture options, both `REDIS` and `KAFKA` can enable when compiling.

    #support output to redis and kafka servers
    make REDIS=1 KAFKA=1

#### Security: `SECURITY_V1` or `SECURITY`

These compile options require `MMT-Security` version 1 or 2 to be installed respectively.

    #support mmt-security
    make SECURITY_V1=1 SECURITY=1

# Execute locally (DPDK):
    #CORE_MASK: hexadecimal bit mask (eg. AAAAAAAAAB)
    sudo ./build/probe -c CORE_MASK -- -c mmt_online.conf
# Execute locally:
    sudo ./probe -c mmt_online.conf

# Execute as service

When executing as service, MMT-Probe uses the default configuration file located at `/opt/mmt/probe/mmt-probe.conf`

    sudo service mmt-probe start
    #see status
    sudo service mmt-probe status
    #stop the service if need
    sudo service mmt-probe stop

# If view data by mmt_operator
    #redis-server
    #goto mmt-operator folder
    #cd mmt-operator
    sudo npm start
    firefox localhost

# This assumes that you have:

## MMT-SDK
    https://bitbucket.org/montimage/mmt-sdk

## MMT-Security
    https://bitbucket.org/montimage/mmt-security

## MMT-Operator
    git clone git@bitbucket.org:montimage/mmt-operator.git
    cd mmt-operator
    npm install
