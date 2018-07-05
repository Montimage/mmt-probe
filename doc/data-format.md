# MMT Data Format


[TOC]

MMT Probe generates data in a flexible format that fits different applications. 

The data format follows this generic structure:

    Common report ⇒ Application report ⇒ Application Sub-Report

Common report is generic to all the report.

## Common report

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 1 | *format id* | Identifier of the format of the encapsulated application report | 
| 2 | *probe*     | Identifier of the probe generating the report | 
| 3 | *source*    | Identifier of the data source whether it is a trace file name or a network interface | 
| 4 | *timestamp* | Timestamp (seconds.micros) corresponding to the time when the output row was reported | 

## Status Report id = 200

It allows us to know that probe is still running even there are no data/traffic in the monitored network.

This report is available only when running in ONLINE mode

This report is created periodically. The period depends on the parameters `stats-period` in the configuration file.

| # | Column Name | Column Description | 
| - | ----------- | ------------------ |
| 5 | *pkt*       | Number of packets being processed since the last reporting moment |
| 6 | *lost*      | Number of packets being dropped since the last reporting moment |

## System Info Report id = 201

This report uses channel name: `cpu.report`, `format id=201`

This report contains statistic of CPU and memory of the machine running mmt-probe.

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 5 | *user cpu*  | Percentage of CPU spent in user mode |
| 6 | *sys cpu*   | Percentage of CPU spent in system mode: e.g., by kernel, interrupt, virtualization, ...|
| 7 | *idle*      | Percentage of CPU spent in idle task |
| 8 | *avail mem* | Available memory in kB |
| 9 | *total mem* | Total memory in kB |


#### Example:
```JSON
201,3,"eth0",1498126191.034157,98.57,0.72,0.72,1597680,2048184
```

## Protocol without Session

Channel name: `protocol.stat`

If protocol without session is enabled, MMT probe will periodically report statistics for detected application and protocols.

### Protocol and Application statistics report has **format id = 99**

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 5 | *report_number* | Number of reporting events |
| 6 | *Protocol/Application ID* | Identifier of the MMT protocol or application. |
| 7 | *Protocol_Path* | Full protocol path. This is to differentiate different paths for the same protocol (like: eth.ip.tcp.http.facebook and eth.ip.tcp.ssl.facebook) |
| 8 | *Nb active flows* | 0 |
| 9 | *Data volume* | Global data volume including headers |
| 10 | *Payload volume* | Global effective data volume (excluding header) |
| 11 | *Packet count* | Global packet count |
| 12 | *UL Data Volume* | 0 |
| 13 | *UL Payload Volume* | 0 |
| 14 | *UL Packet Count* | 0 |
| 15 | *DL Data Volume* | 0 |
| 16 | *DL Payload Volume* | 0 |
| 17 | *DL Packet Count* | 0 |
| 18 | *Start timestamp* | Timestamp (seconds.micros) corresponding to the time when the flow was detected (first packet of the flow) |
| 19 | *Client_Address* | undefined-protocol with session |
| 20 | *Server_Address* | undefined-protocol with session |
| 21 | *MAC source* | undefined |
| 22 | *MAC destination* | undefined |
| 23 | *Session ID* | The protocol does not have session its session id = 0 .|
| 24 | *Server_Port* | 0 |
| 25 | *Client_Port* | 0 |


##### Example:

```JSON
99,0,"./bitdash.pcap",1456138115.568387,30,"99.30",0,1800,1380,30,0,0,0,0,0,0,1456138086.930688,"undefined","undefined","undefined","undefined",0,0,0
```
#### Flow-Protocol and Application statistics report has **format id = 100**

Channel name: `protocol.flow.stat`

This report is a session based reporting (When session report is enable). Session is based on IP source, IP destination, source port and destination port. 

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 5 | *report_number* | Number of reporting events |
| 6 | *Protocol/Application ID* | Identifier of the MMT protocol or application. |
| 7 | *Protocol_Path_uplink* | Full protocol path for uplink. This is to differentiate different paths for the same protocol (like: eth.ip.tcp.http.facebook and eth.ip.tcp.ssl.facebook) |
| 8 | *Protocol_Path_downlink* | Full protocol path for downlink. This is to differentiate different paths for the same protocol (like: eth.ip.tcp.http.facebook and eth.ip.tcp.ssl.facebook) |
| 9 | *Nb active flows* | Number of active flows of the reported protocol for each thread  at the moment of reporting |
| 10 | *Data volume* | Global data volume including headers |
| 11 | *Payload volume* | Global effective data volume (excluding header) |
| 12 | *Packet count* | Global packet count |
| 13 | *UL Data Volume* | Uplink data volume in Bytes |
| 14 | *UL Payload Volume* | Uplink payload data volume in Bytes |
| 15 | *UL Packet Count* | Number of uplink packets |
| 16 | *DL Data Volume* | Downlink data volume in Bytes |
| 17 | *DL Payload Volume* | Downlink payload data volume in Bytes |
| 18 | *DL Packet Count* | Number of downlink packets |
| 19 | *Start timestamp* | Timestamp (seconds.micros) corresponding to the time when the flow was detected (first packet of the flow) |
| 20 | *Client_Address* | Client IP address (source IP address of the first packet of the flow) |
| 21 | *Server_Address* | Server IP address (destination IP address of the first packet of the flow) |
| 22 | *MAC source* | MAC address of the source end |
| 23 | *MAC destination* | MAC address of the destination one |
| 24 | *Session ID* | Identifier of the session for each thread or if the protocol does not have session its session id = 0 .|
| 25 | *Server_Port* | Server port number (0 if transport protocol is session less like ICMP) |
| 26 | *Client_Port* | Client port number (0 if transport protocol is session less like ICMP) |
| 27 | *Thread_number* | Thread number (starts with thread number 0)|
| 28 | *rtt* | rtt at the tcp handshake (SYN-ACK) in usec|
| 29 | *rtt_min_server* | Sampled min server rtt (DATA-ACK) in usec|
| 30 | *rtt_min_client* | Sampled min client rtt (DATA-ACK) in usec|
| 31 | *rtt_max_server* | Sampled max server rtt (DATA-ACK) in usec|
| 32 | *rtt_max_client* | Sampled max client rtt (DATA-ACK) in usec|
| 33 | *rtt_avg_server* | Sampled avg server rtt (DATA-ACK) in usec|
| 34 | *rtt_avg_client* | Sampled avg client rtt (DATA-ACK) in usec|
| 35 | Data_transfer_time  | sample data transfer time in usec (Time difference between  first data packet time and the last packet time received in the sample interval|
| 36 | *retransmission_count* | Sampled TCP retransmission count for each session|
| 37 | *format* | Identifier of the format of the encapsulated application report | 
|    |          | We determine the extension part of report based on this number's value |
| 38 | *Application_Family* | Identifier of the application family (like Web, Network, P2P, etc.). |
| 39 | *Content Class* | Identifier of the content class (like text, image, video, etc.) |

**Note**: only the app/protocol at the end of protocol path (hierarchy) are reported. For example, if a packet has a protocol path `Ethernet.IP.TCP.HTTP` then only `HTTP` is reported. The data volume in the report is length of the packet, the payload volume is the payload of `HTTP` in the packet.

##### Example:

```JSON
100,3,"eth1",1399407481.259615,1,340,"99.178.354.340","99.178.354.340",1,260,128,2,194,128,1,66,0,1,1399407481.189781,"172.19.190.67","92.128.87.243","00:10:c6:b4:7d:92","00:1d:46:f0:87:a1",1,59125,22,0,0,69834,0,69834,0,69834,0,0,0,0,13,0
```
Extension of report 100: The extension provides application specific attributes (HTTP, SSL, FTP, RTP, etc).

Format id: 0 (default)

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 


Format id: 1 (HTTP)

This is reported for each HTTP transaction. If a TCP flow containing 3 HTTP transactions (e.g., `Connection: Keep-Alive`), there will be 3 reports.

| #  | Column Name         | Column Description | 
| -- | ------------------- | ------------------ | 
| 40 | *Response time*     | Interval, in nanosecond, between the request and the response of an HTTP transaction |
| 41 | *Transactions Nb*   | Number of HTTP requests/replies per one TCP session|
| 42 | *Interaction time*  | Interval, in nanosecond, between the first request and the last response. If this is zero then the flow has one request reply |
| 43 | *Hostname*          | Hostname as reported in the HTTP header |
| 44 | *MIME type*         | MIME type of the HTTP reply |
| 45 | *Referrer *         | Referrer as reported in the HTTP header |
| 46 | *CDN_Flag*          | **0**: CDN not detected (This does not mean it is not used :)). **1**: 1 means CDN flags identified in the message. The referrer should identify the application. Will not be present in HTTPS flows. **2**: CDN delivery, the application name should identify the application. However, we might see Akamai as application. In this case, skip it. |
| 47 | *URI *              | URI as reported in the HTTP header |
| 48 | *Method*            | Method as reported in the HTTP header |
| 49 | *Response *         | Response as reported in the HTTP header |
| 50 | Content length      | Content-length as reported in the HTTP header |
| 51 | Req-Res indicator   | It indicates that a particular transaction is finished (with a response) (0: complete, otherwise: >= 1): 1=first block, 2=second block, ..., 0: the last block. This is useful when a long HTTP transition passing through several report periodics. For example, in the first 5 seconds, we see only the request, next 5 seconds, we see nothing concerning this HTTP transaction, then we see its response |

Format id: 2(SSL)

| #  | Column Name  | Column Description | 
| -- | ------------ | ------------------ | 
| 40 | *Servername* | Servername as reported in the SSL/TLS negotiation. It is not always possible to extract this field. will be empty in that case. |
| 41 | *CDN_Flag*   | **0**: CDN not detected (This does not mean it is not used :)). **1**: 1 means CDN flags identified in the message. The referrer should identify the application. Will not be present in HTTPS flows. **2**: CDN delivery, the application name should identify the application. However, we might see Akamai as 

Format id: 3 (RTP)

| #  | Column Name              | Column Description | 
| -- | ------------------------ | ------------------ | 
| 40 | *Packet loss rate*       | Global packet loss rate of the flow | 
| 41 | *Packet loss burstiness* | Average packet loss burstiness of the flow | 
| 42 | *max jitter*             | Maximum jitter value for the flow |
| 43 | *order error*            | Number of order error |


Format id: 4 (FTP)

| #  | Column Name | Column Description | 
| -- |------------ | ------------------ | 
| 40 | *User name* | User name for the particular the ftp session | 
| 41 | *Password*  | Password for the particular ftp session |
| 42 | *File size* | Total size of the file to be downloaded |
| 43 | *File name* | Download file name  |
| 44 | *Direction* | Direction of the flow  |
| 45 | *Control session session_id* | Control session session_id of the corresponding data session  |
| 46 | *Response_time* | Response_time of the file transfer only |

Format id: 5 (GTP)

| #  | Column Name | Column Description | 
| -- | ----------- | ------------------ | 
| 40 | *ip src*    | IP src after GTP | 
| 41 | *ip dst*    | IP dst after GTP |
| 42 | *teid 1*    | First TEID being found in the session | 
| 43 | *teid 2*    | Second TEID being found in the session | 

Format id : 2000 (inside web report (format field), then it is MP2T ) 

| #  | Column Name             | Column Description | 
| -- | ----------------------- | ------------------ | 
| 52 | Average-network_bitrate | Average Network bitrates in bytes/sec of a video segment |
| 53 | Average-video-bitrate   | Average Video bitrates in bytes/sec of a video segment |
| 54 | Retransmission_count    | Retransmission count of a video segment |
| 55 | Out-of-order-count      | out_of_order count of a video segment |
| 56 | Stream-id               | stream id which the segment belongs  |

Format : 2001 (inside web report (formatfield), then it is M3U8 ) 

| #  | Column Name     | Column Description | 
| -- | --------------- | ------------------ | 
| 52 | Version         | Version of M3U8 |
| 53 | Media sequence  | Media Sequence|
| 54 | Target duration | Target duration for each segment |
| 55 | Allow_cache     | Allow cache |


## Security reports

Channel name: `security.report`

Format id: 10

This reports security problems detected by MMT-Security 

| # | Column Name   | Column Description | 
| - | ------------- | ------------------ | 
| 5 | *property_id* | Number: identifying the property |
| 6 | *verdict*     | Word: respected or not respected or detected or not detected giving respectively the status of a security rule and and attack `["detected", "not_detected", "respected", "not_respected", "unknown"]`|
| 7 | *type*        | Word: type of property detected `["attack", "security", "test", "evasion"]`|
| 8 | *cause*       | String: description of the property |
| 9 | *history*     | JSON object: containing a list of events that lead to the verdict. It includes timestamp, either IP or MAC addresses, and the values corresponding to the events of the property that occured

### Example:
```JSON
10,123,"eth1",1452523000.331799,4,"detected","attack","Two successive TCP SYN requests but with different destnation addresses.",{"event_12":{"timestamp":1452523000.158154,"description":"SYN request","attributes":[{"ip.src":"192.168.0.20"},{"ip.dst":"67.196.156.65"},{"tcp.flags":"2"}]},"event_13":{"timestamp":1452523000.329879,"description":"SYN request","attributes":[{"ip.src":"192.168.0.20"},{"ip.dst":"66.235.120.127"},{"tcp.flags":"2"}]}}
```


## HTTP reconstruction reports

Format id: 301

This reports meta data of files being reconstructed from HTTP flows.

| # | Column Name        | Column Description | 
| - | ------------------ | ------------------ | 
| 5 | *status*           | Number: status of reconstructed files:|
|   |                    | - 0: successfully reconstruct |
|   |                    | - 1: did not receive all chunk as declared by `Content-Length` |
|   |                    | - 2: received all chunk data but cannot decode |
|   |                    | - 3: unsupport encoding (currently we support `Content-Encoding: gzip`, `Transfer-Encoding: chunked` |
| 6 | *content-length*   | Number: number of bytes of http flow designed by `Content-Lenght` tag |
| 7 | *received-data*    | Number: number of bytes of data received by MMT |
| 8 | *content-encoding* | Number: identity of `Content-Encoding`  |
|   |                    |  - 0: CONTENT_ENCODING_GZIP,            |
|   |                    |  - 1: CONTENT_ENCODING_COMPRESS,        |
|   |                    |  - 2: CONTENT_ENCODING_DEFLATE,         |
|   |                    |  - 3: CONTENT_ENCODING_IDENTITY,        |
|   |                    |  - 4: CONTENT_ENCODING_BR               |
| 9 | *tranfer-encoding* | Number: identity of `Transfer-Encoding` |
|   |                    |  - 0: TRANSFER_ENCODING_CHUNKED,   |
|   |                    |  - 1: TRANSFER_ENCODING_COMPRESS,  |
|   |                    |  - 2: TRANSFER_ENCODING_DEFLATE,   |
|   |                    |  - 3: TRANSFER_ENCODING_GZIP,      |
|   |                    |  - 4: TRANSFER_ENCODING_IDENTITY   |
| 10| *file-name*        | String: path to reconstructed file |

## Event report

Channel name: `event.report`

Format id: 1000

This reports is for event based reporting. Whenever a event is present, the attributes that are registered for extraction are extracted.

| # | Column Name     | Column Description | 
| - | --------------- | ------------------ | 
| 5 | *report_number* | Number of reporting events |
| 6 | *event*         | Event that triggers the extraction of attributes |
| 7 | *attribute 1*   | Attribute that is registered for extraction  |
| 8 | *attribute 2*   | Attribute that is registered for extraction  |
| ..| *attribute i*   | .... |
### IP Fragmentation event report

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 5 | *evasion_id* | Id of evasion event |
| 6 | *data* | data relate to the evasion event |

With the value of evasion_id and data as follow

| # | evasion_id | value | data | 
| - | -----------| ------|---------- | 
| 1 | EVA_IP_FRAGMENT_PACKET           | 1 | number of fragment in current packet | 
| 2 | EVA_IP_FRAGMENT_SESSION          | 2 | number of fragment in current session | 
| 3 | EVA_IP_FRAGMENTED_PACKET_SESSION | 3 | number of fragmented packet in current session | 
| 4 | EVA_IP_FRAGMENT_OVERLAPPED       | 4 | Type of overlap | 
| 5 | EVA_IP_FRAGMENT_DUPLICATED       | 5 | Type of duplicated | 

Type of overlapped and duplicated:

*      1 - malformed packet (header length mismatch or length mismatch)
*      2 - duplicated fragment
*      3 - overlapped data on the left of the hole
*      4 - overlapped data on the right of the hole
*      5 - overlapped data on both sides of the hole
*      6 - duplicated fragment data


### Example:
```JSON
1000,3,"./p1p1_03.pcap",1399407481.189781,1,172.19.190.67,172.19.190.67
```

## License report

Channel name: `license.stat`

Format id: 30

This reports the statistics of the license owned by the devices

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 1 | *format* | Identifier of the format of the encapsulated application report | 
| 2 | *probe* | Identifier of the probe generating the report | 
| 3 | *source* | Identifier of the data source whether it is a trace file name or a network interface | 
| 4 | *timestamp* | Timestamp (seconds.micros) when the probe was started | 
| 5 | *license_info_id* | Identifier for the the license report |
|   |                   |  1 = BUY_MMT_LICENSE_FOR_THIS_DEVICE
|   |                   |  2 = MMT_LICENSE_EXPIRED
|   |                   |  3 = MMT_LICENSE_WILL_EXPIRE_SOON
|   |                   |  4 = MMT_LICENSE_MODIFIED
|   |                   |  5 = MMT_LICENSE_KEY_DOES_NOT_EXIST
|   |                   |  6 = MMT_LICENSE_INFO |
| 6 | *Number_of_MAC* | Number of MACs which has license |
| 7 | *MAC_address* |Corresponding MAC addresses |
| 8 | *expiry_date* | Timestamp (seconds.micros) when the probe will expire  |
| 9 | *version_probe* | probe_version_gitcommit  |
| 10 | *version_sdk* | sdk_version_gitcommit  |

##### Example:

```JSON
30,0,"xyz.pcap",14356789.233,6,4,"080027749053,0800271C04a5,9C2A70246CDB,B8CA3ACD58D9",15666734.2465,"v0.95-bab7c10","v1.4-0d04f4b"
```
## Security report through socket

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 1 | *Report length (4 bytes)* | Total length of the report | 
| 2 | *Number of attributes(1 bytes)* | Number of attributes present in the particular report | 
| 3 | *Timestamp (16 bytes)* | Time when the report was created | 
| 4 | *Proto-id (4 bytes)* | Identifier of a protocol | 
| 5 | *Attribute-id (4 bytes)* | Identifier for the attribute |
| 6 | *Length* | length of the attribute extracted |
| 7 | *value* | Attribute value |

The fields proto-id, attribute-id, length and value repeats for number of attributes.
