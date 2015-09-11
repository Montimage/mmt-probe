Install `libnetfiler_queue` library:

```sh
sudo apt-get install -y libnfnetlink-dev libmnl-dev
git clone git://git.netfilter.org/libnetfilter_queue
cd libnetfilter_queue/
./configure
make
sudo make install
```

Run an example of using libnetfilter\_queue:

```sh
cd utils/
gcc -o test nfqnl_test.c -lnetfilter_queue -lmnl
sudo ./test
```

You should see the output like:

```sh
opening library handle
unbinding existing nf_queue handler for AF_INET (if any)
binding nfnetlink_queue as nf_queue handler for AF_INET
binding this socket to queue '0'
setting copy_packet mode
setting flags to request UID and GID
setting flags to request security context
Waiting for packets...
pkt received
hw_protocol=0x0800 hook=3 id=1 outdev=2 payload_len=60 
entering callback
pkt received
hw_protocol=0x0800 hook=3 id=2 outdev=2 payload_len=52 
entering callback
pkt received
```
