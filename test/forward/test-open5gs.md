
1. Download, compile, and install the lastest version of mmt-sdk, and mmt-security

- MMT-SDK

  + branch `proto-s1ap`
  + HN tested on the commit [`901a677`](https://bitbucket.org/montimage/mmt-sdk/commits/901a67723fd997b9a2be58194c29d9c206ef018a)

- MMT-Security

  + branch `5greplay`
  + HN tested on the commit [`75d1a14`](https://bitbucket.org/montimage/mmt-security/commits/75d1a1484f411064414df2a61f9fca4cd76b005e)

2. Download and compile mmt-probe

- Code info:
  + branch `replay`
  + HN tested on the commit [`19c5148`](https://bitbucket.org/montimage/mmt-probe/commits/19c51484773ea6e955d74fac2eb7475f32a6c7cb)

- Compile MMT-Probe: `make clean; make DEBUG FORWARD_PACKET_MODULE SECURITY_MODULE compile`

- Compile the example rule: `mkdir rules; /opt/mmt/security/bin/compile_rule rules/forward.so test/forward/forward-localhost.xml`

- Run MMT-Probe: `sudo ./probe -c 5greplay.conf`

3. Start UERANSIM

- Suppose that you installed open5Gs and UERANSIM and MMT in the same machine. And UERANSIM works ok with open5Gs
  + Install open5gs

- Start gNb: `./nr-gnb -c ../config/open5gs-gnb.yaml`

- Start UE: `sudo ./nr-ue -c ../config/open5gs-ue.yaml`

- Note: 
  + If you see this message in gNb: `[ngap] [error] UE context not found with id: 1`, then: restart gNb by pressing Ctrl+c to stop it and start it again, and, restart UE
  + After some stop/start, open5Gs AFM crashed

4. Execution logs

- MMT


```
mmt@mmt ~/hn/mmt-probe >>> sudo ./probe -c 5greplay.conf
mmt-probe: Must not run debug mode in production environment
DEBUG /home/mmt/hn/mmt-probe/src/configure.c:144: security.ip-encapsulation-index = 16
DEBUG /home/mmt/hn/mmt-probe/src/configure.c:850: Parsing block 'reconstruct-data ftp'
DEBUG /home/mmt/hn/mmt-probe/src/configure.c:850: Parsing block 'reconstruct-data http'
mmt-probe: Loaded configuration from '5greplay.conf'
mmt-probe: Start MMT-Security 1.2.11 (75d1a14 - May 12 2021 17:01:10)
mmt-probe: MMT-Probe v1.4.3 (115b2793 - May 12 2021 17:09:05) is running on pid 29875
mmt-probe: Modules: DPI, FORWARD_PACKET, PCAP, REPORT, SECURITY, debug
mmt-probe: MMT-DPI 1.7.0.0 (9baaf9d)
mmt-probe: Starting PCAP mode to analyze 'lo' using the main thread
DEBUG /home/mmt/hn/mmt-probe/src/worker.c:139: Starting worker 0
mmt-probe: Overridden the security parameter 'input.max_message_size' by 60000
INFO_SEC: MMT-Security 1.2.11 (75d1a14 - May 12 2021 17:01:10) is verifying 1 rules having 3 proto.atts using the main thread
mmt-probe: Registered 3 proto.atts to process 1 rules: ip.src,sctp.dest_port,sctp.ch_type
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 46 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 0.67 pps, 714.67 bps
Statistics of forwarded packets 0.67 pps, 714.67 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 50 SCTP_DATA offset: 62
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 52 SCTP_DATA offset: 62
mmt-probe: 164,0,82,0,9313,0 % dropped by NIC 0.0000, by MMT 0.0000
164,0,82,0,9313,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 118 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 1.00 pps, 1114.67 bps
Statistics of forwarded packets 1.00 pps, 1114.67 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 160 SCTP_DATA offset: 62
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 172 SCTP_DATA offset: 62
mmt-probe: 520,0,260,0,37758,0 % dropped by NIC 0.0000, by MMT 0.0000
520,0,260,0,37758,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 322 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 1.00 pps, 1040.00 bps
Statistics of forwarded packets 1.00 pps, 1040.00 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 326 SCTP_DATA offset: 62
mmt-probe: 692,0,346,0,47186,0 % dropped by NIC 0.0000, by MMT 0.0000
692,0,346,0,47186,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 365 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 1.33 pps, 1514.67 bps
Statistics of forwarded packets 1.33 pps, 1514.67 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 523 SCTP_DATA offset: 62
mmt-probe: 1184,0,592,0,89126,0 % dropped by NIC 0.0000, by MMT 0.0000
1184,0,592,0,89126,0 % dropped by NIC 0.0000, by MMT 0.0000
mmt-probe: 1296,0,648,0,95161,0 % dropped by NIC 0.0000, by MMT 0.0000
1296,0,648,0,95161,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 670 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 0.44 pps, 412.44 bps
Statistics of forwarded packets 0.44 pps, 412.44 bps
mmt-probe: 1564,0,782,0,114432,0 % dropped by NIC 0.0000, by MMT 0.0000
1564,0,782,0,114432,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 800 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 0.50 pps, 536.00 bps
Statistics of forwarded packets 0.50 pps, 536.00 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 804 SCTP_DATA offset: 62
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 874 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 1.00 pps, 1136.00 bps
Statistics of forwarded packets 1.00 pps, 1136.00 bps
mmt-probe: 2060,0,1030,0,155083,0 % dropped by NIC 0.0000, by MMT 0.0000
2060,0,1030,0,155083,0 % dropped by NIC 0.0000, by MMT 0.0000
mmt-probe: 2138,0,1069,0,159266,0 % dropped by NIC 0.0000, by MMT 0.0000
2138,0,1069,0,159266,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 1112 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 0.25 pps, 268.00 bps
Statistics of forwarded packets 0.25 pps, 268.00 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 1116 SCTP_DATA offset: 62
mmt-probe: 2282,0,1141,0,167527,0 % dropped by NIC 0.0000, by MMT 0.0000
2282,0,1141,0,167527,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 1178 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 0.67 pps, 714.67 bps
Statistics of forwarded packets 0.67 pps, 714.67 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 1182 SCTP_DATA offset: 62
mmt-probe: 2408,0,1204,0,174525,0 % dropped by NIC 0.0000, by MMT 0.0000
2408,0,1204,0,174525,0 % dropped by NIC 0.0000, by MMT 0.0000
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 1232 SCTP_DATA offset: 62
mmt-probe: Statistics of forwarded packets 1.33 pps, 1514.67 bps
Statistics of forwarded packets 1.33 pps, 1514.67 bps
DEBUG /home/mmt/hn/mmt-probe/src/modules/security/forward/forward_packet.c:79: 1348 SCTP_DATA offset: 62
```


- gNb


```
mmt@mmt ~/hn/UERANSIM/build >>> ./nr-gnb -c ../config/open5gs-gnb.yaml 
UERANSIM v3.1.8
[2021-05-12 17:22:58.395] [sctp] [info] Trying to establish SCTP connection... (127.0.0.5:38412)
[2021-05-12 17:22:58.397] [sctp] [info] SCTP connection established (127.0.0.5:38412)
[2021-05-12 17:22:58.397] [sctp] [debug] SCTP association setup ascId[318]
[2021-05-12 17:22:58.398] [ngap] [debug] Sending NG Setup Request
[2021-05-12 17:22:58.398] [ngap] [debug] NG Setup Response received
[2021-05-12 17:22:58.398] [ngap] [info] NG Setup procedure is successful
[2021-05-12 17:23:04.741] [rls] [debug] New UE signal detected, total [1] UEs in coverage
[2021-05-12 17:23:04.744] [rrc] [info] RRC Setup for UE[1]
[2021-05-12 17:23:04.745] [ngap] [debug] Initial NAS message received from UE[1]
[2021-05-12 17:23:04.749] [ngap] [debug] UE Context Release Command received
[2021-05-12 17:23:04.749] [rrc] [info] Releasing RRC connection for UE[1]
[2021-05-12 17:23:04.752] [ngap] [error] UE context not found with id: 1
^Cmmt@mmt ~/hn/UERANSIM/build >>> ./nr-gnb -c ../config/open5gs-gnb.yaml 
UERANSIM v3.1.8
[2021-05-12 17:23:10.170] [sctp] [info] Trying to establish SCTP connection... (127.0.0.5:38412)
[2021-05-12 17:23:10.173] [sctp] [info] SCTP connection established (127.0.0.5:38412)
[2021-05-12 17:23:10.173] [sctp] [debug] SCTP association setup ascId[320]
[2021-05-12 17:23:10.173] [ngap] [debug] Sending NG Setup Request
[2021-05-12 17:23:10.174] [ngap] [debug] NG Setup Response received
[2021-05-12 17:23:10.174] [ngap] [info] NG Setup procedure is successful
[2021-05-12 17:23:10.764] [rls] [debug] New UE signal detected, total [1] UEs in coverage
[2021-05-12 17:23:13.966] [rls] [debug] New UE signal detected, total [2] UEs in coverage
[2021-05-12 17:23:13.968] [rrc] [info] RRC Setup for UE[2]
[2021-05-12 17:23:13.969] [ngap] [debug] Initial NAS message received from UE[2]
[2021-05-12 17:23:13.980] [ngap] [debug] Initial Context Setup Request received
[2021-05-12 17:23:13.984] [ngap] [debug] UE Context Release Command received
[2021-05-12 17:23:13.984] [ngap] [error] Error indication received. Cause: radio-network/unknown-local-UE-NGAP-ID
[2021-05-12 17:23:13.984] [ngap] [error] UE context not found with id: 2
[2021-05-12 17:23:13.984] [ngap] [error] UE context not found with id: 2
[2021-05-12 17:23:13.984] [rrc] [info] Releasing RRC connection for UE[2]
[2021-05-12 17:23:16.173] [rls] [debug] Signal lost detected for UE[1]
[2021-05-12 17:23:16.173] [ngap] [debug] Sending UE Context release request (NG-RAN node initiated)
[2021-05-12 17:23:16.173] [ngap] [error] UE context not found with id: 1
[2021-05-12 17:23:22.539] [rls] [debug] New UE signal detected, total [2] UEs in coverage
[2021-05-12 17:23:22.542] [rrc] [info] RRC Setup for UE[3]
[2021-05-12 17:23:22.542] [ngap] [debug] Initial NAS message received from UE[3]
[2021-05-12 17:23:22.545] [ngap] [debug] UE Context Release Command received
[2021-05-12 17:23:22.545] [rrc] [info] Releasing RRC connection for UE[3]
[2021-05-12 17:23:24.177] [rls] [debug] Signal lost detected for UE[2]
[2021-05-12 17:23:24.177] [ngap] [debug] Sending UE Context release request (NG-RAN node initiated)
[2021-05-12 17:23:24.177] [ngap] [error] UE context not found with id: 2
^Cmmt@mmt ~/hn/UERANSIM/build >>> ./nr-gnb -c ../config/open5gs-gnb.yaml 
UERANSIM v3.1.8
[2021-05-12 17:23:26.795] [sctp] [info] Trying to establish SCTP connection... (127.0.0.5:38412)
[2021-05-12 17:23:26.797] [sctp] [info] SCTP connection established (127.0.0.5:38412)
[2021-05-12 17:23:26.797] [sctp] [debug] SCTP association setup ascId[322]
[2021-05-12 17:23:26.798] [ngap] [debug] Sending NG Setup Request
[2021-05-12 17:23:26.799] [ngap] [debug] NG Setup Response received
[2021-05-12 17:23:26.799] [ngap] [info] NG Setup procedure is successful
[2021-05-12 17:23:30.661] [rls] [debug] New UE signal detected, total [1] UEs in coverage
[2021-05-12 17:23:30.664] [rrc] [info] RRC Setup for UE[1]
[2021-05-12 17:23:30.665] [ngap] [debug] Initial NAS message received from UE[1]
[2021-05-12 17:23:30.675] [ngap] [debug] Initial Context Setup Request received
[2021-05-12 17:23:30.677] [ngap] [debug] UE Context Release Command received
[2021-05-12 17:23:30.677] [rrc] [info] Releasing RRC connection for UE[1]
[2021-05-12 17:23:30.680] [ngap] [error] UE context not found with id: 1
[2021-05-12 17:23:30.681] [ngap] [error] UE context not found with id: 1
[2021-05-12 17:23:36.800] [rls] [debug] Signal lost detected for UE[1]
[2021-05-12 17:23:36.800] [ngap] [debug] Sending UE Context release request (NG-RAN node initiated)
[2021-05-12 17:23:36.800] [ngap] [error] UE context not found with id: 1
^Cmmt@mmt ~/hn/UERANSIM/build >>> ./nr-gnb -c ../config/open5gs-gnb.yaml 
UERANSIM v3.1.8
[2021-05-12 17:23:38.452] [sctp] [info] Trying to establish SCTP connection... (127.0.0.5:38412)
[2021-05-12 17:23:38.454] [sctp] [info] SCTP connection established (127.0.0.5:38412)
[2021-05-12 17:23:38.454] [sctp] [debug] SCTP association setup ascId[324]
[2021-05-12 17:23:38.454] [ngap] [debug] Sending NG Setup Request
[2021-05-12 17:23:38.455] [ngap] [debug] NG Setup Response received
[2021-05-12 17:23:38.455] [ngap] [info] NG Setup procedure is successful



^Cmmt@mmt ~/hn/UERANSIM/build >>> ./nr-gnb -c ../config/open5gs-gnb.yaml 
UERANSIM v3.1.8
[2021-05-12 17:23:44.157] [sctp] [info] Trying to establish SCTP connection... (127.0.0.5:38412)
[2021-05-12 17:23:44.159] [sctp] [info] SCTP connection established (127.0.0.5:38412)
[2021-05-12 17:23:44.159] [sctp] [debug] SCTP association setup ascId[326]
[2021-05-12 17:23:44.160] [ngap] [debug] Sending NG Setup Request
[2021-05-12 17:23:44.161] [ngap] [debug] NG Setup Response received
[2021-05-12 17:23:44.161] [ngap] [info] NG Setup procedure is successful
[2021-05-12 17:23:47.057] [rls] [debug] New UE signal detected, total [1] UEs in coverage
[2021-05-12 17:23:47.059] [rrc] [info] RRC Setup for UE[1]
[2021-05-12 17:23:47.060] [ngap] [debug] Initial NAS message received from UE[1]
[2021-05-12 17:23:47.069] [ngap] [debug] UE Context Release Command received
[2021-05-12 17:23:47.071] [rrc] [info] Releasing RRC connection for UE[1]
[2021-05-12 17:23:47.192] [sctp] [debug] SCTP association shutdown (clientId: 2)
[2021-05-12 17:23:47.192] [sctp] [warning] Unhandled SCTP notification received
terminate called after throwing an instance of 'sctp::SctpError'
  what():  SCTP receive message failure: Connection reset by peer
Aborted (core dumped)
```

- UE


```
mmt@mmt ~/hn/UERANSIM/build >>> 
mmt@mmt ~/hn/UERANSIM/build >>> sudo ./nr-ue -c ../config/open5gs-ue.yaml
UERANSIM v3.1.8
[2021-05-12 17:23:04.742] [nas] [info] UE switches to state [MM-DEREGISTERED/PLMN-SEARCH]
[2021-05-12 17:23:04.743] [rls] [debug] Coverage change detected. [1] cell entered, [0] cell exited
[2021-05-12 17:23:04.743] [nas] [info] Serving cell determined [UERANSIM-gnb-901-70-1]
[2021-05-12 17:23:04.743] [nas] [info] UE switches to state [MM-DEREGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:04.743] [nas] [debug] Sending Initial Registration
[2021-05-12 17:23:04.743] [nas] [info] UE switches to state [MM-REGISTER-INITIATED/NA]
[2021-05-12 17:23:04.743] [rrc] [debug] Sending RRC Setup Request
[2021-05-12 17:23:04.745] [rrc] [info] RRC connection established
[2021-05-12 17:23:04.745] [nas] [info] UE switches to state [CM-CONNECTED]
[2021-05-12 17:23:04.750] [rrc] [debug] RRC Release received
[2021-05-12 17:23:04.750] [nas] [info] UE switches to state [CM-IDLE]
[2021-05-12 17:23:04.750] [nas] [info] UE switches to state [MM-DEREGISTERED/NA]
[2021-05-12 17:23:04.750] [nas] [info] UE switches to state [5U2-NOT-UPDATED]
[2021-05-12 17:23:04.750] [nas] [info] UE switches to state [MM-DEREGISTERED/ATTEMPTING-REGISTRATION]
^Cmmt@mmt ~/hn/UERANSIM/build >>> sudo ./nr-ue -c ../config/open5gs-ue.yaml
UERANSIM v3.1.8
[2021-05-12 17:23:13.966] [nas] [info] UE switches to state [MM-DEREGISTERED/PLMN-SEARCH]
[2021-05-12 17:23:13.968] [rls] [debug] Coverage change detected. [1] cell entered, [0] cell exited
[2021-05-12 17:23:13.968] [nas] [info] Serving cell determined [UERANSIM-gnb-901-70-1]
[2021-05-12 17:23:13.968] [nas] [info] UE switches to state [MM-DEREGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:13.968] [nas] [debug] Sending Initial Registration
[2021-05-12 17:23:13.968] [nas] [info] UE switches to state [MM-REGISTER-INITIATED/NA]
[2021-05-12 17:23:13.968] [rrc] [debug] Sending RRC Setup Request
[2021-05-12 17:23:13.968] [rrc] [info] RRC connection established
[2021-05-12 17:23:13.969] [nas] [info] UE switches to state [CM-CONNECTED]
[2021-05-12 17:23:13.973] [nas] [debug] Security Mode Command received
[2021-05-12 17:23:13.973] [nas] [debug] Selected integrity[0] ciphering[0]
[2021-05-12 17:23:13.983] [nas] [debug] Registration accept received
[2021-05-12 17:23:13.983] [nas] [info] UE switches to state [MM-REGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:13.983] [nas] [info] Initial Registration is successful
[2021-05-12 17:23:13.983] [nas] [info] Initial PDU sessions are establishing [1#]
[2021-05-12 17:23:13.983] [nas] [debug] Sending PDU Session Establishment Request
[2021-05-12 17:23:13.985] [rrc] [debug] RRC Release received
[2021-05-12 17:23:13.985] [nas] [info] UE switches to state [CM-IDLE]
^Cmmt@mmt ~/hn/UERANSIM/build >>> sudo ./nr-ue -c ../config/open5gs-ue.yaml
UERANSIM v3.1.8
[2021-05-12 17:23:22.539] [nas] [info] UE switches to state [MM-DEREGISTERED/PLMN-SEARCH]
[2021-05-12 17:23:22.541] [rls] [debug] Coverage change detected. [1] cell entered, [0] cell exited
[2021-05-12 17:23:22.541] [nas] [info] Serving cell determined [UERANSIM-gnb-901-70-1]
[2021-05-12 17:23:22.541] [nas] [info] UE switches to state [MM-DEREGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:22.541] [nas] [debug] Sending Initial Registration
[2021-05-12 17:23:22.541] [nas] [info] UE switches to state [MM-REGISTER-INITIATED/NA]
[2021-05-12 17:23:22.541] [rrc] [debug] Sending RRC Setup Request
[2021-05-12 17:23:22.542] [rrc] [info] RRC connection established
[2021-05-12 17:23:22.542] [nas] [info] UE switches to state [CM-CONNECTED]
[2021-05-12 17:23:22.546] [rrc] [debug] RRC Release received
[2021-05-12 17:23:22.546] [nas] [info] UE switches to state [CM-IDLE]
[2021-05-12 17:23:22.546] [nas] [info] UE switches to state [MM-DEREGISTERED/NA]
[2021-05-12 17:23:22.546] [nas] [info] UE switches to state [5U2-NOT-UPDATED]
[2021-05-12 17:23:22.546] [nas] [info] UE switches to state [MM-DEREGISTERED/ATTEMPTING-REGISTRATION]
^Cmmt@mmt ~/hn/UERANSIM/build >>> sudo ./nr-ue -c ../config/open5gs-ue.yaml
UERANSIM v3.1.8
[2021-05-12 17:23:30.661] [nas] [info] UE switches to state [MM-DEREGISTERED/PLMN-SEARCH]
[2021-05-12 17:23:30.663] [rls] [debug] Coverage change detected. [1] cell entered, [0] cell exited
[2021-05-12 17:23:30.663] [nas] [info] Serving cell determined [UERANSIM-gnb-901-70-1]
[2021-05-12 17:23:30.663] [nas] [info] UE switches to state [MM-DEREGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:30.663] [nas] [debug] Sending Initial Registration
[2021-05-12 17:23:30.663] [nas] [info] UE switches to state [MM-REGISTER-INITIATED/NA]
[2021-05-12 17:23:30.663] [rrc] [debug] Sending RRC Setup Request
[2021-05-12 17:23:30.664] [rrc] [info] RRC connection established
[2021-05-12 17:23:30.664] [nas] [info] UE switches to state [CM-CONNECTED]
[2021-05-12 17:23:30.671] [nas] [debug] Security Mode Command received
[2021-05-12 17:23:30.671] [nas] [debug] Selected integrity[0] ciphering[0]
[2021-05-12 17:23:30.678] [nas] [debug] Registration accept received
[2021-05-12 17:23:30.678] [nas] [info] UE switches to state [MM-REGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:30.678] [nas] [info] Initial Registration is successful
[2021-05-12 17:23:30.678] [nas] [info] Initial PDU sessions are establishing [1#]
[2021-05-12 17:23:30.678] [nas] [debug] Sending PDU Session Establishment Request
[2021-05-12 17:23:30.680] [rrc] [debug] RRC Release received
[2021-05-12 17:23:30.680] [nas] [info] UE switches to state [CM-IDLE]
^Cmmt@mmt ~/hn/UERANSIM/build >>> sudo ./nr-ue -c ../config/open5gs-ue.yaml
UERANSIM v3.1.8
[2021-05-12 17:23:47.058] [nas] [info] UE switches to state [MM-DEREGISTERED/PLMN-SEARCH]
[2021-05-12 17:23:47.059] [rls] [debug] Coverage change detected. [1] cell entered, [0] cell exited
[2021-05-12 17:23:47.059] [nas] [info] Serving cell determined [UERANSIM-gnb-901-70-1]
[2021-05-12 17:23:47.059] [nas] [info] UE switches to state [MM-DEREGISTERED/NORMAL-SERVICE]
[2021-05-12 17:23:47.059] [nas] [debug] Sending Initial Registration
[2021-05-12 17:23:47.059] [nas] [info] UE switches to state [MM-REGISTER-INITIATED/NA]
[2021-05-12 17:23:47.059] [rrc] [debug] Sending RRC Setup Request
[2021-05-12 17:23:47.059] [rrc] [info] RRC connection established
[2021-05-12 17:23:47.059] [nas] [info] UE switches to state [CM-CONNECTED]
[2021-05-12 17:23:47.065] [nas] [debug] Security Mode Command received
[2021-05-12 17:23:47.065] [nas] [debug] Selected integrity[0] ciphering[0]
[2021-05-12 17:23:47.071] [rrc] [debug] RRC Release received
[2021-05-12 17:23:47.071] [nas] [info] UE switches to state [CM-IDLE]
[2021-05-12 17:23:47.071] [nas] [info] UE switches to state [MM-DEREGISTERED/NA]
[2021-05-12 17:23:47.071] [nas] [info] UE switches to state [5U2-NOT-UPDATED]
[2021-05-12 17:23:47.071] [nas] [info] UE switches to state [MM-DEREGISTERED/ATTEMPTING-REGISTRATION]
```

- open5Gs AMF


```
mmt@mmt ~/hn/UERANSIM/build >>> tail -f /var/log/open5gs/amf.log 
/lib/x86_64-linux-gnu/libpthread.so.0(+0x76db) [0x7fb946b7a6db]
/lib/x86_64-linux-gnu/libc.so.6(clone+0x3f) [0x7fb9468a3a3f]
Open5GS daemon v2.2.7

05/12 17:11:36.007: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:129)
05/12 17:11:36.007: [app] INFO: File Logging: '/var/log/open5gs/amf.log' (../lib/app/ogs-init.c:132)
05/12 17:11:36.010: [sbi] INFO: nghttp2_server() [127.0.0.5]:7777 (../lib/sbi/nghttp2-server.c:145)
05/12 17:11:36.011: [amf] INFO: ngap_server() [127.0.0.5]:38412 (../src/amf/ngap-sctp.c:54)
05/12 17:11:36.012: [sctp] INFO: AMF initialize...done (../src/amf/app.c:33)
05/12 17:11:36.013: [amf] INFO: [57f212f6-b334-41eb-9cc3-1716509eb889] NF registred [Heartbeat:10s] (../src/amf/nf-sm.c:199)


05/12 17:22:55.296: [amf] INFO: gNB-N2 accepted[127.0.0.1]:46613 in ng-path module (../src/amf/ngap-sctp.c:106)
05/12 17:22:55.296: [amf] INFO: gNB-N2 accepted[127.0.0.1] in master_sm module (../src/amf/amf-sm.c:588)
05/12 17:22:55.296: [amf] INFO: [GNB] max_num_of_ostreams : 30 (../src/amf/context.c:849)
05/12 17:22:55.296: [amf] INFO: [Added] Number of gNBs is now 1 (../src/amf/context.c:865)
05/12 17:22:58.397: [amf] INFO: gNB-N2 accepted[127.0.0.1]:47343 in ng-path module (../src/amf/ngap-sctp.c:106)
05/12 17:22:58.397: [amf] INFO: gNB-N2 accepted[127.0.0.1] in master_sm module (../src/amf/amf-sm.c:588)
05/12 17:22:58.397: [amf] INFO: [GNB] max_num_of_ostreams : 30 (../src/amf/context.c:849)
05/12 17:22:58.397: [amf] INFO: [Added] Number of gNBs is now 2 (../src/amf/context.c:865)
05/12 17:23:04.745: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:04.745: [amf] INFO: [Added] Number of gNB-UEs is now 1 (../src/amf/context.c:1933)
05/12 17:23:04.745: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[1] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:04.745: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] Unknown UE by SUCI (../src/amf/context.c:1326)
05/12 17:23:04.745: [amf] INFO: [Added] Number of AMF-UEs is now 1 (../src/amf/context.c:1139)
05/12 17:23:04.745: [gmm] INFO: Registration request (../src/amf/gmm-sm.c:131)
05/12 17:23:04.745: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:04.745: [app] WARNING: Try to discover [AUSF] (../lib/sbi/path.c:109)
05/12 17:23:04.746: [amf] INFO: [25962abe-b1a8-41eb-9637-f13c86603e7a] (NF-discover) NF registered (../src/amf/nnrf-handler.c:332)
05/12 17:23:04.746: [amf] INFO: [25962abe-b1a8-41eb-9637-f13c86603e7a] (NF-discover) NF Profile updated (../src/amf/nnrf-handler.c:391)
05/12 17:23:04.748: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:04.748: [amf] INFO: [Added] Number of gNB-UEs is now 2 (../src/amf/context.c:1933)
05/12 17:23:04.748: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:04.748: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:04.748: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:04.748: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:04.748: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:04.749: [amf] INFO: UE Context Release [Action:1] (../src/amf/ngap-handler.c:1274)
05/12 17:23:04.749: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[1] (../src/amf/ngap-handler.c:1276)
05/12 17:23:04.749: [amf] INFO: [Removed] Number of gNB-UEs is now 1 (../src/amf/context.c:1939)
05/12 17:23:04.751: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:04.751: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:04.751: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:04.751: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:04.751: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:04.760: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:04.760: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:04.760: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:04.760: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:04.761: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:04.764: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:04.764: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:04.764: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:04.764: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:04.764: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:04.765: [amf] ERROR: No RAN UE Context : AMF_UE_NGAP_ID[1] (../src/amf/ngap-handler.c:1250)
05/12 17:23:04.765: [amf] ERROR: No RAN UE Context : AMF_UE_NGAP_ID[1] (../src/amf/ngap-handler.c:1250)
05/12 17:23:09.168: [amf] INFO: gNB-N2[127.0.0.1] connection refused!!! (../src/amf/amf-sm.c:636)
05/12 17:23:09.168: [amf] INFO: [Removed] Number of gNBs is now 1 (../src/amf/context.c:893)
05/12 17:23:10.173: [amf] INFO: gNB-N2 accepted[127.0.0.1]:37439 in ng-path module (../src/amf/ngap-sctp.c:106)
05/12 17:23:10.173: [amf] INFO: gNB-N2 accepted[127.0.0.1] in master_sm module (../src/amf/amf-sm.c:588)
05/12 17:23:10.173: [amf] INFO: [GNB] max_num_of_ostreams : 30 (../src/amf/context.c:849)
05/12 17:23:10.173: [amf] INFO: [Added] Number of gNBs is now 2 (../src/amf/context.c:865)
05/12 17:23:13.969: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:13.969: [amf] INFO: [Added] Number of gNB-UEs is now 2 (../src/amf/context.c:1933)
05/12 17:23:13.969: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[3] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:13.969: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:13.969: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:13.969: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:13.969: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:13.973: [app] WARNING: Try to discover [UDM] (../lib/sbi/path.c:109)
05/12 17:23:13.974: [amf] INFO: [25d033a8-b1a8-41eb-b102-fd4cca47fe36] (NF-discover) NF registered (../src/amf/nnrf-handler.c:332)
05/12 17:23:13.974: [amf] INFO: [25d033a8-b1a8-41eb-b102-fd4cca47fe36] (NF-discover) NF Profile updated (../src/amf/nnrf-handler.c:391)
05/12 17:23:13.977: [app] WARNING: Try to discover [PCF] (../lib/sbi/path.c:109)
05/12 17:23:13.977: [amf] INFO: [2c397c40-b1a8-41eb-8546-09e00cf06f84] (NF-discover) NF registered (../src/amf/nnrf-handler.c:332)
05/12 17:23:13.978: [amf] INFO: [2c397c40-b1a8-41eb-8546-09e00cf06f84] (NF-discover) NF Profile updated (../src/amf/nnrf-handler.c:391)
05/12 17:23:13.980: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:13.981: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:13.981: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:13.981: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:982)
05/12 17:23:13.981: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:13.981: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:13.983: [amf] ERROR: Cannot find AMF-UE Context [3] (../src/amf/ngap-handler.c:812)
05/12 17:23:13.983: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:13.983: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:13.983: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:13.983: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:13.984: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:13.984: [amf] INFO: UE Context Release [Action:1] (../src/amf/ngap-handler.c:1274)
05/12 17:23:13.984: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[3] (../src/amf/ngap-handler.c:1276)
05/12 17:23:13.984: [amf] INFO: [Removed] Number of gNB-UEs is now 1 (../src/amf/context.c:1939)
05/12 17:23:13.996: [amf] ERROR: No RAN UE Context : AMF_UE_NGAP_ID[3] (../src/amf/ngap-handler.c:798)
05/12 17:23:13.996: [amf] ERROR: No RAN UE Context : AMF_UE_NGAP_ID[3] (../src/amf/ngap-handler.c:798)
05/12 17:23:22.543: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:22.543: [amf] INFO: [Added] Number of gNB-UEs is now 2 (../src/amf/context.c:1933)
05/12 17:23:22.543: [amf] INFO:     RAN_UE_NGAP_ID[2] AMF_UE_NGAP_ID[4] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:22.543: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:22.543: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:22.543: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:22.543: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:22.545: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:22.545: [amf] INFO: [Added] Number of gNB-UEs is now 3 (../src/amf/context.c:1933)
05/12 17:23:22.545: [amf] INFO:     RAN_UE_NGAP_ID[2] AMF_UE_NGAP_ID[5] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:22.545: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:22.545: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:22.545: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:22.545: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:22.545: [amf] INFO: UE Context Release [Action:1] (../src/amf/ngap-handler.c:1274)
05/12 17:23:22.545: [amf] INFO:     RAN_UE_NGAP_ID[2] AMF_UE_NGAP_ID[4] (../src/amf/ngap-handler.c:1276)
05/12 17:23:22.545: [amf] INFO: [Removed] Number of gNB-UEs is now 2 (../src/amf/context.c:1939)
05/12 17:23:22.546: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:22.546: [amf] INFO:     RAN_UE_NGAP_ID[2] AMF_UE_NGAP_ID[5] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:22.546: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:22.546: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:22.546: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:26.057: [amf] INFO: gNB-N2[127.0.0.1] connection refused!!! (../src/amf/amf-sm.c:636)
05/12 17:23:26.057: [amf] INFO: [Removed] Number of gNBs is now 1 (../src/amf/context.c:893)
05/12 17:23:26.797: [amf] INFO: gNB-N2 accepted[127.0.0.1]:58751 in ng-path module (../src/amf/ngap-sctp.c:106)
05/12 17:23:26.798: [amf] INFO: gNB-N2 accepted[127.0.0.1] in master_sm module (../src/amf/amf-sm.c:588)
05/12 17:23:26.798: [amf] INFO: [GNB] max_num_of_ostreams : 30 (../src/amf/context.c:849)
05/12 17:23:26.798: [amf] INFO: [Added] Number of gNBs is now 2 (../src/amf/context.c:865)
05/12 17:23:30.665: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:30.665: [amf] INFO: [Added] Number of gNB-UEs is now 3 (../src/amf/context.c:1933)
05/12 17:23:30.665: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[6] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:30.665: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:30.665: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:30.665: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:30.666: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:30.676: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:30.676: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:30.676: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:30.676: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:982)
05/12 17:23:30.676: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:30.676: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:30.678: [amf] INFO: UE Context Release [Action:1] (../src/amf/ngap-handler.c:1274)
05/12 17:23:30.678: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[6] (../src/amf/ngap-handler.c:1276)
05/12 17:23:30.678: [amf] INFO: [Removed] Number of gNB-UEs is now 2 (../src/amf/context.c:1939)
05/12 17:23:30.679: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:30.679: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:30.679: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:30.679: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:30.679: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:37.511: [amf] INFO: gNB-N2[127.0.0.1] connection refused!!! (../src/amf/amf-sm.c:636)
05/12 17:23:37.511: [amf] INFO: [Removed] Number of gNBs is now 1 (../src/amf/context.c:893)
05/12 17:23:38.454: [amf] INFO: gNB-N2 accepted[127.0.0.1]:34565 in ng-path module (../src/amf/ngap-sctp.c:106)
05/12 17:23:38.454: [amf] INFO: gNB-N2 accepted[127.0.0.1] in master_sm module (../src/amf/amf-sm.c:588)
05/12 17:23:38.454: [amf] INFO: [GNB] max_num_of_ostreams : 30 (../src/amf/context.c:849)
05/12 17:23:38.454: [amf] INFO: [Added] Number of gNBs is now 2 (../src/amf/context.c:865)
05/12 17:23:43.286: [amf] INFO: gNB-N2[127.0.0.1] connection refused!!! (../src/amf/amf-sm.c:636)
05/12 17:23:43.286: [amf] INFO: [Removed] Number of gNBs is now 1 (../src/amf/context.c:893)
05/12 17:23:44.159: [amf] INFO: gNB-N2 accepted[127.0.0.1]:40269 in ng-path module (../src/amf/ngap-sctp.c:106)
05/12 17:23:44.159: [amf] INFO: gNB-N2 accepted[127.0.0.1] in master_sm module (../src/amf/amf-sm.c:588)
05/12 17:23:44.159: [amf] INFO: [GNB] max_num_of_ostreams : 30 (../src/amf/context.c:849)
05/12 17:23:44.159: [amf] INFO: [Added] Number of gNBs is now 2 (../src/amf/context.c:865)
05/12 17:23:47.060: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:47.060: [amf] INFO: [Added] Number of gNB-UEs is now 3 (../src/amf/context.c:1933)
05/12 17:23:47.060: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[7] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:47.060: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:47.060: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:508)
05/12 17:23:47.060: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:47.060: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:47.068: [amf] INFO: InitialUEMessage (../src/amf/ngap-handler.c:350)
05/12 17:23:47.068: [amf] INFO:     RAN_UE_NGAP_ID[1] AMF_UE_NGAP_ID[2] TAC[1] CellID[0x10] (../src/amf/ngap-handler.c:484)
05/12 17:23:47.068: [amf] INFO: [suci-0-901-70-0000-0-0-0000000001] known UE by SUCI (../src/amf/context.c:1324)
05/12 17:23:47.069: [gmm] WARNING: Registration request (../src/amf/gmm-sm.c:982)
05/12 17:23:47.069: [gmm] INFO: [suci-0-901-70-0000-0-0-0000000001]    SUCI (../src/amf/gmm-handler.c:72)
05/12 17:23:47.069: [amf] WARNING: GUTI has already been allocated (../src/amf/context.c:1045)
05/12 17:23:47.070: [gmm] ERROR: Invalid service name [nudm-sdm] (../src/amf/gmm-sm.c:625)
05/12 17:23:47.070: [gmm] WARNING: gmm_state_authentication: should not be reached. (../src/amf/gmm-sm.c:626)
05/12 17:23:47.070: [core] FATAL: backtrace() returned 9 addresses (../lib/core/ogs-abort.c:37)
/usr/bin/open5gs-amfd(+0x17418) [0x55f750b1d418]
/usr/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x16) [0x7ff86bb4ec76]
/usr/bin/open5gs-amfd(+0x1bb4e) [0x55f750b21b4e]
/usr/lib/x86_64-linux-gnu/libogscore.so.2(ogs_fsm_dispatch+0x16) [0x7ff86bb4ec76]
/usr/bin/open5gs-amfd(+0x5ec6) [0x55f750b0bec6]
/usr/lib/x86_64-linux-gnu/libogscore.so.2(+0xd718) [0x7ff86bb46718]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x76db) [0x7ff869f416db]
/lib/x86_64-linux-gnu/libc.so.6(clone+0x3f) [0x7ff869c6aa3f]
Open5GS daemon v2.2.7

05/12 17:23:49.271: [app] INFO: Configuration: '/etc/open5gs/amf.yaml' (../lib/app/ogs-init.c:129)
05/12 17:23:49.271: [app] INFO: File Logging: '/var/log/open5gs/amf.log' (../lib/app/ogs-init.c:132)
05/12 17:23:49.273: [sbi] INFO: nghttp2_server() [127.0.0.5]:7777 (../lib/sbi/nghttp2-server.c:145)
05/12 17:23:49.274: [amf] INFO: ngap_server() [127.0.0.5]:38412 (../src/amf/ngap-sctp.c:54)
05/12 17:23:49.274: [sctp] INFO: AMF initialize...done (../src/amf/app.c:33)
05/12 17:23:49.274: [amf] INFO: [0d013ee6-b336-41eb-8d3b-2f5556fe06ad] NF registred [Heartbeat:10s] (../src/amf/nf-sm.c:199)
^C
```
