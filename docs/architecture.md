Normally MMT-Probe consists of 3 processes:

- monitor process: this is the root. It creates the two children processes below and monitors them: it recreates a child if the child has been crashed.
- processing process: this is the main processing. It realizes the main function of MMT-Probe.
- control process: this is an optional process. It is activated or disabled depeding on the configuration of MMT-Probe. It opens an UNIX socket to internally listen control commands. After being validated, a received control command will be forward to the processing process and the monitor process. Either the monitor process or the processing process will react depending on the type of commands.  


```
start =========== monitor proc ================>> end
       |\                            |  |
       | `======= processing proc ==='  |
       |                                |
       '========= control proc ========='
       
          +----------------------------------------------------------------------------------+
          |                                   +-------------+                                |
          |                                  /             /|                                |
- NIC     |          +------------+         +-------------+ |        +----------+            |
- pcap    | traffic  |            |  create |             | | create |          |   commands |     +--------+
==========|=========>| processing |<--------| monitoring  |--------->| control  |<===========|=====|        |
          | reports  |   proc.    | die     |    proc.    | |    die |  proc.   | responses  |     |  UNIX  |
<=========|==========|            |-------->|             |<---------|          |============|====>| socket |
- files   |          |            |         |             |/         |          |            |     |        |
- redis   |          +------------+         +-------------+          +----------+            |     +--------+
- mongodb |                                                                                  |
- socket  +----------------------------------------------------------------------------------+
- kafka
```