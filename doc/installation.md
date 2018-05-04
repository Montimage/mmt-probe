# Installation

Before installing MMT-probe, we need to install MMT-SDKx. To compile and install  MMT-SDK follow the instructions in MMT-SDK section [here](https://bitbucket.org/montimage/mmt-sdk/wiki/Compilation%20and%20Installation%20Instructions).

## Prerequisites

MMT-probe requires certain software packages to be installed beforehand . Following are the list of packages along with their installation and compilation instructions.

### Step 1 — Installing Required Packages

#### GCC 4.9 or later

```bash
sudo su 
apt-get install build-essential
add-apt-repository ppa:ubuntu-toolchain-r/test
apt-get update
apt-get install gcc-4.9 g++-4.9 cpp-4.9

#after that if you check the version of gcc you will find the old version
gcc --version

#so we can fix it with simple symbolic
cd /usr/bin
rm gcc g++ cpp
ln -s gcc-4.9 gcc
ln -s g++-4.9 g++
ln -s cpp-4.9 cpp
```

#### Confuse library

This library is used to parse the configuration file.

```bash
sudo apt-get install libconfuse-dev
```


#### Optional requirements

There exist some other optional requirements that depend on compile parameters when compiling.
They will be detaillede just below. 


### Step 2 — Compile & Install MMT-probe

Download MMT-Probe from bitbucket

```
git clone https://bitbucket.org/montimage/mmt-probe.git
```


#### Compile the probe

Using GNU Make to compile probe: `make <options> action`. User can press `<tab>` key, `make <tab>`, to obtain the list of _options_ and _actions_ as the following:

```
mmt@ubuntu:~/mmt-probe$ make 
DEBUG             MONGODB_MODULE    VERBOSE           install
DISABLE_REPORT    PCAP_DUMP_MODULE  all               keygen
DPDK_CAPTURE      REDIS_MODULE      clean             rpm
KAFKA_MODULE      SECURITY_MODULE   deb               
LICENSE_MODULE    SIMPLE_REPORT     dist-clean
```

The options are in uppercase, while the action are in lowercase. 
For example, to compile MMT-Probe to use DPDK: `make DPDK_CAPTURE all`

#### Options Compile 
    
##### `VERBOSE` 

This option prints detail about compiling process
    
##### `DEBUG`
This option enable `-g -O0` compile flags to be able to use `gdb` to debug

##### `LICENSE_MODULE`
This enables probe to check license information when starting. If no license is found or it is expired, probe will exit immediately.

##### `DISABLE_REPORT`

Do not perform DPI statistics such as, session report, event report, etc.
Consequently no DPI reports will be output.

This option is very helpful if user want to get higher performance for security or dumping network packets to pcap files.

###### `SIMPLE_REPORT`

This option enables a simple version of DPI reports: only some attributes (source and desstination of IP, MAC, port number; and upload and download volumes) session report. It is used for MMT-Box.

##### `DPDK`

MMT-Probe supports either libpcap or dpdk to capture packets.
Libpcap is selected by default. 

```bash
#Use DPDK
make DPDK_CAPTURE all
#Use PCAP
make all
```

##### **Output modules**:  `REDIS_MODULE`, `KAFKA_MODULE`, `MONGODB_MODULE`

In addition to output reports to files, MMT-Probe can ouput to redis, kafka and mongodb servers. 

**Install required libraries**

- When output to redis, we need `hiredis` library

```bash
# install hiredis library
git clone https://github.com/redis/hiredis.git
cd hiredis
make
sudo make install
sudo ldconfig
```

- When output to kafka, we need `librdkafka`

```bash
#install librdkafka (C/C++ kafka client library)
sudo apt-get install -y libsasl2-dev libssl-dev # required by librdkafka
git clone https://github.com/edenhill/librdkafka.git
cd librdkafka
./configure
make
sudo make install
sudo ldconfig
```


- When output to mongodb, we need [`libmongo` and `libbson`](http://mongoc.org/libmongoc/current/installing.html)

```bash
sudo apt-get install pkg-config libssl-dev libsasl2-dev
wget https://github.com/mongodb/mongo-c-driver/releases/download/1.9.5/mongo-c-driver-1.9.5.tar.gz
tar xzf mongo-c-driver-1.9.5.tar.gz
cd mongo-c-driver-1.9.5
./configure --disable-automatic-init-and-cleanup
```

**Compile MMT-Probe **

```bash
#support output to file, redis and kafka servers
make REDIS_MODULE KAFKA_MODULE all
#or support only output to file and mongodb server
make MONGODB_MODULE all
```
    
##### `SECURITY_MODULE`

These compile options require `MMT-Security` to be installed respectively (see https://bitbucket.org/montimage/mmt-security).

```bash
#support mmt-security
make SECURITY_MODULE all
```

###### `PCAP_DUMP_MODULE`

###### `DYNAMIC_CONFIG_MODULE`

Enable to modify configuration parameters at runtime

###### `NETCONF_MODULE`

By default, the dynamic reconfiguration receives new parameters via socket. This option enable the reception via net_conf protocol.

This compile option requires `Sysrepo` and `netopeer2 server`.

###### Reconstruction modules: `HTTP-RECONSTRUCT_MODULE`, `FTP_RECONSTRCT_MODULE`

This option enables reconstruction of tcp payload

#### Compile actions

- `all`: compile source code to obtain executable file `probe`
- `clean`: clean files generated by compiler, such as, .o file
- `keygen`: compile serial key generator program
- `install`: install MMT-Probe on the current machine
- `dist-clean`: remove MMT-Probe that was installed by `install` action
- `deb`: create debian-based package (tested on Debian, Ubuntu)
- `rpm`: create REL-based package (tested on CentOS, Fedora)



### Step 3 — Execution

When running `./probe -h` (or `./probe -- -h` in DPDK mode), we obtain:

```
mmt@ubuntu:~/mmt-probe$ ./probe -h
./probe [<option>]
Option:
   -v               : Print version information, then exits.
   -c <config file> : Gives the path to the configuration file (default: ./mmt-probe.conf, /opt/mmt/probe/mmt-probe.conf).
   -t <trace file>  : Gives the trace file for offline analyse.
   -i <interface>   : Gives the interface name for live traffic analysis.
   -X attr=value    : Override configuration attributes.
                       For example "-X file-output.enable=true -Xfile-output.output-dir=/tmp/" will enable output to file and change output directory to /tmp.
                       This parameter can appear several times.
   -x               : Prints list of configuration attributes being able to be used with -X, then exits.
   -h               : Prints this help, then exits.
```

#### Execute locally (DPDK):

```bash
#CORE_MASK: hexadecimal bit mask (eg. AAAAAAAAAB)
sudo ./probe -c CORE_MASK -- -c mmt-probe.conf
```

#### Execute locally (PCAP):

```bash
sudo ./probe -c mmt-probe.conf
```

#### Execute as service

When executing as service, MMT-Probe uses the default configuration file located at `/opt/mmt/probe/mmt-probe.conf`

```bash
sudo service mmt-probe start
#see status
sudo service mmt-probe status
#stop the service if need
sudo service mmt-probe stop
```

#### Execution log

Probe writes it execution log using `syslog`. To view the log, do `journalctl -t mmt-probe`
