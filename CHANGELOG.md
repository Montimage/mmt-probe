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