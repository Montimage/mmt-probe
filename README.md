# MMT Probe

## Documentation

* [About](https://bitbucket.org/montimage/mmt-probe/wiki/About/)
* [Installation](https://bitbucket.org/montimage/mmt-probe/wiki/Installation/)
* [Configuration](https://bitbucket.org/montimage/mmt-probe/wiki/Configuration/)
* [Data Format](https://bitbucket.org/montimage/mmt-probe/wiki/Data Format/)
* [User Guide](https://bitbucket.org/montimage/mmt-probe/wiki/User Guide/)
* [Developer Guide](https://bitbucket.org/montimage/mmt-probe/wiki/Developer Guide/)

## Getting Started
```
# Compile the Ericsson probe. with:
gcc -o probe src/smp_main.c src/processing.c src/thredis.c -lmmt_core -ldl -lpcap -lconfuse -lhiredis -lpthread
# execute:
sudo su
./probe -c ./mmt_online.con
#if using redis and mmt_operator
redis-server
node app.js -d mongo
firefox localhost:8088


# Compile the simple probe with:
gcc -o simple_probe src/main.c -lmmt_core -ldl -lpcap
# Execute: 
./simple_probe <pcap file>

# This assumes that you have compiled MMT SDK and install it on your system
# If this is not the case:

> cd [mmt_folder]/sdk
> make -j4
> sudo make install

# Before executing, insure you have created "plugins" forder and have either copied the TCPIP plugin or created a symbolic link to it.
```