# Installation

Before installing MMT-probe, we need to install MMT-DPI. 

To compile and install  MMT-DPI follow the instructions in MMT-DPI section [here](https://github.com/montimage/mmt-dpi/).

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
git clone https://github.com/montimage/mmt-probe.git
```


#### Compile the probe

```
cd mmt-probe
make
sudo make install
```

Using GNU Make to compile probe: `make <options> action`. User can press `<tab>` key, `make <tab>`, to obtain the list of _options_ and _actions_ as the following:

```
mmt@ubuntu:~/mmt-probe$ make 
ALL_MODULES              NETCONF_MODULE           clean
DEBUG                    PCAP_DUMP_MODULE         deb
DISABLE_REPORT           QOS_MODULE               dist-clean
DPDK_CAPTURE             REDIS_MODULE             gperf
DYNAMIC_CONFIG_MODULE    SECURITY_MODULE          gperf-clean
FTP_RECONSTRUCT_MODULE   SIMPLE_REPORT            install
HTTP_RECONSTRUCT_MODULE  SOCKET_MODULE            keygen
KAFKA_MODULE             TCP_REASSEMBLY_MODULE    rpm
LICENSE_MODULE           VERBOSE                  
MONGODB_MODULE           compile                    
```

The options are in *UPPERCASE*, while the action are in *lowercase*. 
For example, to compile MMT-Probe to use DPDK: `make DPDK_CAPTURE compile`

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

##### `SIMPLE_REPORT`

This option enables a simple version of DPI reports: only some attributes (source and desstination of IP, MAC, port number; and upload and download volumes) session report. It is used for MMT-Box.

##### `DPDK_CAPTURE`

MMT-Probe supports either libpcap or dpdk to capture packets.
Libpcap is selected by default. 

```bash
#Use DPDK
make DPDK_CAPTURE compile
#Use PCAP
make compile
```

##### **Output modules**:  `REDIS_MODULE`, `KAFKA_MODULE`, `MONGODB_MODULE`

In addition to output reports to files, MMT-Probe can ouput to redis, kafka and mongodb servers. 

Install required libraries

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
make
sudo make install
```

Compile MMT-Probe:

```bash
#support output to file, redis and kafka servers
make REDIS_MODULE KAFKA_MODULE compile
#or support only output to file and mongodb server
make MONGODB_MODULE compile
```
    
##### `SECURITY_MODULE`

These compile options require `MMT-Security` to be installed respectively (see https://github.com/montimage/mmt-security).

```bash
#support mmt-security
make SECURITY_MODULE compile
```

##### `PCAP_DUMP_MODULE`

Add a module to dump packets to pcap files

##### `DYNAMIC_CONFIG_MODULE`

Add a module allowing to modify configuration parameters at runtime

##### `NETCONF_MODULE`

By default, the dynamic reconfiguration receives new parameters via socket. This option enable the reception via net_conf protocol.

This compile option requires `Sysrepo` and `netopeer2 server`.

##### Reconstruction modules: `HTTP-RECONSTRUCT_MODULE`, `FTP_RECONSTRCT_MODULE`

This option enables reconstruction of tcp payload

##### `ALL_MODULES` 

Add all modules in probe. 

```bash
make ALL_MODULE compile
```

#### Compile actions

- `compile`: compile source code to obtain executable file `probe`
- `clean`: clean files generated by compiler, such as, .o file
- `keygen`: compile serial key generator program
- `install`: install MMT-Probe on the current machine
- `dist-clean`: remove MMT-Probe that was installed by `install` action
- `deb`: create debian-based package (tested on Debian, Ubuntu)
- `rpm`: create REL-based package (tested on CentOS, Fedora)
- `gperf`: generate code files by gperf tool to take into account perfect hashing
- `gperf-clean`: delete the code files generated by gperf tool

#### Other options

##### `MMT_BASE=xxxx`

This option specify a based-folder on which the MMT toolchains have been installed:

- when using with `make install MMT_BASE=/tmp/mmt`, then MMT-Probe will be installed on `/tmp/mmt/probe` instead of its default folder `/opt/mmt/probe`
- This option also needs when MMT-DPI and MMT-Security are not installed in the default folders. So makefile will try to find DPI and Security in `/tmp/mmt` instead of `/opt/mmt`

##### `STATIC_LINK`

This option links statically MMT-DPI (`mmt_core` + `mmt_tcpip`) and MMT-Security into MMT-Probe.
This is, the executable binary file of MMT-Probe contains these libraries.
Consequently we do not need to install these libraries into a new machine when installing MMT-Probe, 
only one executable file is enough. 

Currently, the following libraries will be statically linked (embedded) into probe:

- libmmt-dpi
- libmmt-security2
- libpcap
- libconfuse
- libhiredis

### Step 3 — Execution

When running `./probe -h`, we obtain:

```bash
mmt@ubuntu:~/mmt-probe$ ./probe -h
./probe [<option>]
Option:
   -v               : Print version information, then exits.
   -c <config file> : Gives the path to the configuration file (default: ./mmt-probe.conf, /opt/mmt/probe/mmt-probe.conf).
   -t <trace file>  : Gives the trace file for offline analyse.
   -i <interface>   : Gives the interface name for live traffic analysis.
   -X attr=value    : Override configuration attributes.
                       For example "-X file-output.enable=true -Xfile-output.output-dir=/tmp/" will enable output to file and change output directory to /tmp.
                       The parameter -X can appear several times.
   -x               : Prints list of configuration attributes being able to be used with -X, then exits.
   -h               : Prints this help, then exits.
```

#### Execute locally:

```bash
sudo ./probe -c mmt-probe.conf
```

#### Execute as service

The MMT-Probe service is available only when MMT-Probe is installed in to its default folder, at `/opt/mmt/probe`. Thus when it is compiled with option `MMT_BASE=...`, the service will not be generated. When generating service, MMT-Probe needs to be installed under `root` permission. However when `MMT_BASE` is present, user wants to install MMT to another folder, without root, so MMT-Probe cannot introduce its service.

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
