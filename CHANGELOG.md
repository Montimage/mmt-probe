## v1.5.7
- update mmt-security to filter SCTP by port number
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