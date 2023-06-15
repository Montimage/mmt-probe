## v1.5.12
- fixed bug rejecting -X param having same value

## v1.5.11
- support output the reports to an UDP socket
- support customized output format of the event-based reports.
- fixed issue in Kafka output which cache messages in the output queue
- fixed issue when using `-Xsecurity.exclude-rules` parameter which is not intialized beforehand
- fixed format of LPI output messages
 
## v1.5.10 (17 May 2023)
- add Light-Packet-Inspection to analyse quickly packets which come from malicious actors, such as DDoS attacks, which cause high resource consumption on Deep-Packet-Inspection
- bump new version of MMT-DPI which supports HTTP2 and MMT-Security which includes 2 rules to detect HTTP2 attacks

## v1.5.9 (23 Mar 2023)
- update mmt-security which introduces 2 rules to detect DoS attacks in 5G control plane

## v1.5.8 (14 Dec 2022)
- auto reconnect to Kafka bus when timeout or failled

## v1.5.7
- update mmt-security to filter SCTP by port number
- fix minor typo in k8s guide 

## v1.5.6
- use new security rules to detect 5G corrupted packets
- new DPI to fix the limit of 16 bit of `RAN_UE_ID`

## v1.5.5
- 30 June 2022
- Reactive statistic of number of packets dropped by NIC, by MMT

## v1.5.4
- 27 June 2022
- fixed bug in dtls security rule (rule 79)
- fixed bug in error message when capturing in incomptable ethernet NIC
      
## v1.5.2
- 14 April 2022
- Support `query-report`:
   + group attribute values to calculate new values such as, `avg` (average), `sum` (total), `var` (variance), `count` (counter)
   + configurable report period that independs with `stats-period` parameter
   + use millisecond as period unit of `query-report`

## v1.5.1
- 24 Feb 2022
- Support `proto.index.att` syntax in `event-report`
- Add `delta-cond` in `event-report` to issue an report only if there is a change in a set of attributes
- Improve `event-report` trigger mechanisme to be called only one when the whole packet is classified
- Fixed bug when `output-channel` always containt `file-output`
- Fixed bug that does not dump no-session packets to pcap files
- Add all options/component when being packaged in a container
- Add `. Aborted` word when explicitly aborting the current execution

## v1.5.0
- 15 Feb 2022
- Support any protocol stack. For example when `stack-type=178` the root protocol is IP (rather than Ethernet as by default)
- Add `stack-offset` to ignore some prefixed bytes when analysing packet

## v1.4.4
- 29 March 2021
- Add `rtt-base` config parameter to decide which timestamp-base to calcultate RTT

## v1.4.3

- 17 March 2021
- Fixed bug in dynamic configuration: blocking when receiving command
- Change command format: Each command is now ended by '\0' (null byte) 