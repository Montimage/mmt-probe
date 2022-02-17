# MMT Data Format


[TOC]

MMT Probe generates data in a flexible format that fits different applications.
By default, the reports use CSV format:

- separator using comma `,`
- a string is surrounded by `"` and `"`, for example, `"eth1"`
- new line character is `\n` 
- a complex value is surrounded by `[` and `]`, for example, `"eth1",[1,2],5`



The data format follows this generic structure:

    Common report ==> Application report ==> Application Sub-Report

Common report is generic to all the report.

## Common report

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 1 | *format id* | Identifier of the format of the encapsulated application report | 
| 2 | *probe*     | Identifier of the probe generating the report | 
| 3 | *source*    | Identifier of the data source whether it is a trace file name or a network interface | 
| 4 | *timestamp* | Timestamp (seconds.micros). Depending the kind of report, it represents the moment |
|   |             | - either in realtime (report id = 201)  |
|   |             | - or in the packet's time (other reports)  | 

## Status Report id = 200

It allows us to know that probe is still running even there are no data/traffic in the monitored network.

This report is available only when running in `ONLINE` mode

This report is created periodically. The period depends on the parameters `stats-period` in the configuration file.

| # | Column Name | Column Description | 
| - | ----------- | ------------------ |
| 5 | *nic-pkt*   | Number of packets being received by NIC |
| 6 | *nic-lost*  | Number of packets being dropped by NIC  |
| 7 | *mmt-pkt*   | Number of packets being received by MMT |
| 8 | *mmt-lost*  | Number of packets being dropped by MMT  |
| 9 | *mmt-bytes* | Number of bytes being received by MMT   |
| 10| *mmt-b-lost*| Number of bytes being dropped by MMT    |

## System Info Report id = 201

This report contains statistic of CPU and memory of the machine running mmt-probe.

| # | Column Name | Column Description | 
| - | ----------- | ------------------ | 
| 5 | *user cpu*  | Percentage of CPU spent in user mode |
| 6 | *sys cpu*   | Percentage of CPU spent in system mode: e.g., by kernel, interrupt, virtualization, ...|
| 7 | *idle*      | Percentage of CPU spent in idle task |
| 8 | *avail mem* | Available memory in kB |
| 9 | *total mem* | Total memory in kB     |


#### Example:
```JSON
201,3,"eth0",1498126191.034157,98.57,0.72,0.72,1597680,2048184
```

## Protocol without Session

If protocol without session is enabled, MMT probe will periodically report statistics for detected application and protocols.

### Protocol and Application statistics report has **format id = 99**

| #  | Column Name         | Column Description | 
| -  | ------------------- | ------------------ | 
| 5  | *report_number*     | Number of reporting events |
| 6  | *Protocol/App ID*   | Identifier of the MMT protocol or application. |
| 7  | *Protocol_Path*     | Full protocol path. This is to differentiate different paths for the same protocol (like: eth.ip.tcp.http.facebook and eth.ip.tcp.ssl.facebook) |
| 8  | *Nb active flows*   | 0 |
| 9  | *Data volume*       | Global data volume including headers |
| 10 | *Payload volume*    | Global effective data volume (excluding header) |
| 11 | *Packet count*      | Global packet count |
| 12 | *UL Data Volume*    | 0 |
| 13 | *UL Payload Volume* | 0 |
| 14 | *UL Packet Count*   | 0 |
| 15 | *DL Data Volume*    | 0 |
| 16 | *DL Payload Volume* | 0 |
| 17 | *DL Packet Count*   | 0 |
| 18 | *Start timestamp*   | Timestamp (seconds.micros) corresponding to the time when the flow was detected (first packet of the flow) |


##### Example:

```JSON
99,0,"./bitdash.pcap",1456138115.568387,30,"99.30",0,1800,1380,30,0,0,0,0,0,0,1456138086.930688
```
#### Flow-Protocol and Application statistics report has **format id = 100**

This report is a session based reporting (When session report is enable). Session is based on IP source, IP destination, source port and destination port. 

| #  | Column Name | Column Description | 
| -  | ----------- | ------------------ | 
| 5  | *report_number* | Number of reporting events |
| 6  | *Protocol/App ID* | Identifier of the MMT protocol or application. |
| 7  | *Protocol_Path_uplink* | Full protocol path for uplink. This is to differentiate different paths for the same protocol (like: eth.ip.tcp.http.facebook and eth.ip.tcp.ssl.facebook) |
| 8  | *Protocol_Path_downlink* | Full protocol path for downlink. This is to differentiate different paths for the same protocol (like: eth.ip.tcp.http.facebook and eth.ip.tcp.ssl.facebook) |
| 9  | *Nb active flows* | Number of active flows of the reported protocol for each thread  at the moment of reporting |
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
| 28 | *handshake_time* | interval, in microsecond, of 3-way handshake|
| 29 | *app_response_time* | interval, in microsecond, between the last packet in 3-way handshake, (ACK packet - when session established), and the first data packet being transmitted after that|
| 30 | *data_transfer_time* | interval, in microsecond, from the current sampling packet to the latest packet being reported. The sum `(handshake_time + app_response_time + data_transfer_time)` represents timelife of a tcp session. It allows to measure EURT (end-user response time) |
| 31 | *client_rtt_data_min* | Sampled min client rtt (DATA-ACK) in microsecond. `rtt_data` is the rounded trip time of a data packet (the one not in 3-way handshake process). `client_rtt_data` is the interval between an client data packet and its ACK. When several data packets are acknowledged by only one ACK, then they have the same `rtt_data` that is calculated by the interval between the last data packet and the ACK|
| 32 | *server_rtt_data_min* | Sampled min server rtt (DATA-ACK) in microsecond|
| 33 | *client_rtt_data_max* | Sampled max client rtt (DATA-ACK) in microsecond|
| 34 | *server_rtt_data_max* | Sampled max server rtt (DATA-ACK) in microsecond|
| 35 | *client_rtt_data_avg* | Sampled avg client rtt (DATA-ACK) in microsecond. This is not `min + max/2` but the average rtt time of all packets captured in the sampled period.|
| 36 | *server_rtt_data_avg* | Sampled avg server rtt (DATA-ACK) in microsecond|
| 37 | *client_retransmission* | Sampled TCP retransmission count for client direction|
| 38 | *server_retransmission* | Sampled TCP retransmission count for server direction|
| 39 | *format* | Identifier of the format of the encapsulated application report | 
|    |          | We determine the extension part of report based on this number's value |
| 40 | *Application_Family* | Identifier of the application family (like Web, Network, P2P, etc.). |
| 41 | *Content Class* | Identifier of the content class (like text, image, video, etc.) |

**Note**: only the app/protocol at the end of protocol path (hierarchy) are reported. For example, if a packet has a protocol path `Ethernet.IP.TCP.HTTP` then only `HTTP` is reported. The data volume in the report is length of the packet, the payload volume is the payload of `HTTP` in the packet.

##### Example:

```JSON
100,3,"./1-tcp.pcap",1470228655.713042,1,153,"99.178.354.153","99.178.354.153",1,945,269,10,462,124,5,483,145,5,1470228652.710419,"10.13.13.103","10.13.13.102","08:00:27:9A:E2:E2","08:00:27:F0:BD:EA",1,8080,59916,0,0,225,47,0,0,156,47,0,0,0,0,0,1,0
```
Extension of report 100: The extension provides application specific attributes (HTTP, SSL, FTP, RTP, etc).

**Note** If `SIMPLE_REPORT` is activated when compiling MMT-Probe, the session reports will be compact.
It contains less information than default:

| #  | Column Name      | Column Description | 
| -  | ---------------- | ------------------ | 
| 5  | *report_number*  | Number of reporting events |
| 6  | *Protocol_Path*  | Full protocol path |
| 7  | *Packet count*   | Global packet count |
| 8  | *UL Data Volume* | Uplink data volume in Bytes |
|  9 | *DL Data Volume* | Downlink data volume in Bytes |
| 10 | *Client_Address* | Client IP address (source IP address of the first packet of the flow) |
| 11 | *Server_Address* | Server IP address (destination IP address of the first packet of the flow) |
| 12 | *MAC source*     | MAC address of the source end |
| 13 | *MAC dest*       | MAC address of the destination one |
| 14 | *Server_Port*    | Server port number |
| 15 | *Client_Port*    | Client port number |

For example:

```JSON
100,3,"../share_box/pcap/bigFlows.pcap",1361916155.971019,1,0,"99.178.354.0",60,0,"172.16.133.82","96.43.146.50","00:21:70:63:3B:AD","00:90:7F:3E:02:D0",443,61237
```

**Format id: 0 (default)**

| # | Column Name | Column Description | 
| - | ----------- | ------------------ |
|   |             |                    |


**Format id: 1 (HTTP)**

This is reported for each HTTP transaction. If a TCP flow containing 3 HTTP transactions (e.g., `Connection: Keep-Alive`), there will be 3 reports.

| #  | Column Name         | Column Description | 
| -- | ------------------- | ------------------ | 
| 42 | *Response time*     | Interval, in microsecond, between the request and the response of an HTTP transaction |
| 43 | *Transactions Nb*   | Number of HTTP requests/replies per one TCP session|
| 44 | *Interaction time*  | Interval, in microsecond, between the first request and the last response. If this is zero then the flow has one request reply |
| 45 | *Hostname*          | Hostname as reported in the HTTP header |
| 46 | *MIME type*         | MIME type of the HTTP reply |
| 47 | *Referrer *         | Referrer as reported in the HTTP header |
| 48 | *CDN_Flag*          | **0**: CDN not detected (This does not mean it is not used :)). **1**: 1 means CDN flags identified in the message. The referrer should identify the application. Will not be present in HTTPS flows. **2**: CDN delivery, the application name should identify the application. However, we might see Akamai as application. In this case, skip it. |
| 49 | *URI *              | URI as reported in the HTTP header |
| 50 | *Method*            | Method as reported in the HTTP header |
| 51 | *Response *         | Response as reported in the HTTP header |
| 52 | Content length      | Content-length as reported in the HTTP header |
| 53 | Req-Res indicator   | It indicates that a particular transaction is finished (with a response) (0: complete, otherwise: >= 1): 1=first block, 2=second block, ..., 0: the last block. This is useful when a long HTTP transition passing through several report periodics. For example, in the first 5 seconds, we see only the request, next 5 seconds, we see nothing concerning this HTTP transaction, then we see its response |

**Format id: 2 (SSL)**

| #  | Column Name  | Column Description | 
| -- | ------------ | ------------------ | 
| 42 | *Servername* | Servername as reported in the SSL/TLS negotiation. It is not always possible to extract this field. will be empty in that case. |
| 43 | *CDN_Flag*   | **0**: CDN not detected (This does not mean it is not used :)). **1**: 1 means CDN flags identified in the message. The referrer should identify the application. Will not be present in HTTPS flows. **2**: CDN delivery, the application name should identify the application. However, we might see Akamai as 

**Format id: 3 (RTP)**

| #  | Column Name              | Column Description | 
| -- | ------------------------ | ------------------ | 
| 42 | *Packet loss rate*       | Global packet loss rate of the flow | 
| 43 | *Packet loss burstiness* | Average packet loss burstiness of the flow | 
| 44 | *max jitter*             | Maximum jitter value for the flow |
| 45 | *order error*            | Number of order error |


**Format id: 4 (FTP)**

| #  | Column Name | Column Description | 
| -- |------------ | ------------------ | 
| 42 | *User name* | User name for the particular the ftp session | 
| 43 | *Password*  | Password for the particular ftp session |
| 44 | *File size* | Total size of the file to be downloaded |
| 45 | *File name* | Download file name     |
| 46 | *Direction* | Direction of the flow  |
| 47 | *Control session id* | Control session session_id of the corresponding data session  |
| 48 | *Response_time* | Response_time of the file transfer only |

**Format id: 5 (GTP) **

| #  | Column Name | Column Description | 
| -- | ----------- | ------------------ | 
| 42 | *ip src*    | Source of the first IP after Ethernet. The one of IP after GTP is in main part of the report, at index 20  | 
| 43 | *ip dst*    |  Destination of the first IP after Ethernet. The one of IP after GTP is in main part of the report, at index 21  |
| 44 | *TEIDs*     | Array of TEID numbers, surrounded by `[` and `]` |

**Format id : 2000 (inside web report (format field), then it is MP2T ) **

| #  | Column Name             | Column Description | 
| -- | ----------------------- | ------------------ | 
| 54 | Average-network_bitrate | Average Network bitrates in bytes/sec of a video segment |
| 55 | Average-video-bitrate   | Average Video bitrates in bytes/sec of a video segment |
| 56 | Retransmission_count    | Retransmission count of a video segment |
| 57 | Out-of-order-count      | out_of_order count of a video segment |
| 58 | Stream-id               | stream id which the segment belongs  |

**Format : 2001 (inside web report (formatfield), then it is M3U8 ) **

| #  | Column Name     | Column Description | 
| -- | --------------- | ------------------ | 
| 54 | Version         | Version of M3U8 |
| 55 | Media sequence  | Media Sequence|
| 56 | Target duration | Target duration for each segment |
| 57 | Allow_cache     | Allow cache |


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
10,123,"eth1",1452523000.331799,4,"detected","attack","Two successive TCP SYN requests but with different destnation addresses.",{"event_12":{"timestamp":1452523000.158154,"description":"SYN request","attributes":[["ip.src","192.168.0.20"],["ip.dst","67.196.156.65"],["tcp.flags","2"]]},"event_13":{"timestamp":1452523000.329879,"description":"SYN request","attributes":[["ip.src","192.168.0.20"],["ip.dst","66.235.120.127"],["tcp.flags","2"]]}}
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


## eNodeB reports

### eNodeB topology reports

Format id: 400

This report is created when an element in LTE network is added or removed.
An element is identified by its Id.


| # | Column Name       |   Type  | Column Description   | 
| - | ----------------- | ------- | -------------------- | 
| 5 | *element-id*      | Number  | Unique ID of element |
| 6 | *event*           | Number  | Add/remove elements/links  |



An *event* can be:

- 1: Add a new element. The rest of report in this case will contain complement information of the element. Its structure is:

| # | Column Name       |   Type  | Column Description   | 
| - | ----------------- | ------- | -------------------- | 
| 7 | *ip*              | String  | IP of the element. We currently support only IPv4  |
| 8 | *element-type*    | Number  | 1: UE, 2: eNodeB, 3: MME, 4: Packet gateway |
| 9 | *name*            | String  | Name if MME/eNodeB, IMSI if UE |
| 10| *ue.m_tmsi*       | Number  | Only for UE |



- 2: Add a new link between the element and its parent. The rest of report contains the id of the parent.
- 3: Remove all links of the element but it is still resting in the topology, e.g., it is detaching
- 4: Remove the element, thus its associated links will be remove also.



*Example:*

```JSON

```


### eNodeB QoS reports

Format id: 401

This report is created when an UE in LTE network is allocated a dedicated bearer.


| # | Column Name       |   Type  | Column Description   | 
| - | ----------------- | ------- | -------------------- | 
| 5 | *element-id*      | Number  | Unique ID of UE. This ID is generated by MMT |
| 6 | *teid*            | Number  | TEID |
| 7 | *qcI*             | Number  | QoS Class Identifier  |


*Example:*

```JSON

```


## Event report

Channel name: `event.report`

Format id: 1000

This reports is for event based reporting. Whenever a event is present, the attributes that are registered for extraction are extracted.

| # | Column Name     | Column Description | 
| - | --------------- | ------------------ | 
| 5 | *event-id*      | Is a string representing id of event-report |
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

## Startup report

Format id: 1

This report is sent *only once* at starting Probe.

| # | Column Name       | Column Description | 
| - | ----------------- | ------------------ |
| 1 | *format*          | Identifier of the format of the report = 1 |
| 2 | *probe*           | Identifier of the probe generating the report |
| 3 | *source*          | Identifier of the data source whether it is a trace file name or a network interface |
| 4 | *timestamp*       | Timestamp (seconds.micros) *when the probe was started* |
| 5 | *version_probe*   | Version of MMT-Probe |
| 6 | *version_dpi*     | Version of MMT-DPI |
| 7 | *version_security*| Version of MMT-Security if it is enable |

## License report

Channel name: `license.stat`

Format id: 30

This reports the statistics of the license owned by the devices.

| # | Column Name       | Column Description | 
| - | ----------------- | ------------------ |
| 1 | *format*          | Identifier of the format of the report = 30 |
| 2 | *probe*           | Identifier of the probe generating the report |
| 3 | *source*          | Identifier of the data source whether it is a trace file name or a network interface |
| 4 | *timestamp*       | Timestamp (seconds.micros) when the report has been created  |
| 5 | *license_info_id* | Identifier for the the license report |
|   |                   | 1 = BUY_MMT_LICENSE_FOR_THIS_DEVICE |
|   |                   | 2 = MMT_LICENSE_EXPIRED |
|   |                   | 3 = MMT_LICENSE_WILL_EXPIRE_SOON |
|   |                   | 4 = MMT_LICENSE_MODIFIED | 
|   |                   | 5 = MMT_LICENSE_KEY_DOES_NOT_EXIST | 
|   |                   | 6 = MMT_LICENSE_INFO |
| 6 | *Number_of_MAC*   | Number of MACs which has license | 
| 7 | *MAC_address*     |Corresponding MAC addresses |
| 8 | *expiry_date*     | Timestamp (seconds.micros) when the probe will expire |
| 9 | *version_probe*   | Version of MMT-Probe |
| 10 | *version_sdk*    | Version of MMT-DPI |

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
