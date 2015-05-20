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
# Add these two destinations to your library path if it is not the case
export LD_LIBRARY_PATH=/opt/mmt/lib:/usr/local/lib:$LD_LIBRARY_PATH

# Compile the Ericsson probe. with:
gcc -I/opt/mmt/include -o probe src/smp_main.c src/processing.c src/thredis.c -L/opt/mmt/lib -lmmt_core -lmmt_tcpip -ldl -lpcap -lconfuse -lhiredis -lpthread

# Compile the simple probe with:
gcc -I/opt/mmt/include -o simple_probe src/main.c -L/opt/mmt/lib -lmmt_core -lmmt_tcpip -ldl -lpcap

# This assumes that you have compiled MMT SDK and install it on your system
# If this is not the case:

> cd [mmt_folder]/sdk
> make -j4
> sudo make install

# Before executing, insure you have created "plugins" forder and have either copied the TCPIP plugin or created a symbolic link to it.
```