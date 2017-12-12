### 1. Connect to the NETCONF server via SSH to port 830 (username / password is netconf):
```
ssh netconf@(ip where probe is install) -p 830 -s netconf

password: netconf

```
### 2. Send a hello message and get running config:
```
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<capabilities>
<capability>urn:ietf:params:neconf:base:1.0</capability>
<capability>urn:ietf:params:netconf:base:1.1</capability>
<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>
</capabilities>
</hello>
]]>]]>

#139
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<get-config>
<source>
<running />
</source>
</get-config>
</rpc>
##
```
### 3. Following XML scrits provide some of the examples to make changes on the probe configuration (as per the requirement). This XML scripts are based on yang model.

#### 3.1 enable output-to-file

```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><file-output xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable></file-output></config></edit-config></rpc>
##
```
#### 3.2 enable output-to-redis

```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><redis-output xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><hostname>192.168.0.34</hostname><port>6379</port></redis-output></config></edit-config></rpc>
##

```
#### 3.3 enable output-to-kafka

```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><kafka-output xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><hostname>192.168.0.18</hostname><port>9092</port></kafka-output></config></edit-config></rpc>
##

```

#### 3.4 enable session-report and output to redis (enable output to redis beforehand)

```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><session-report xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><output_to_redis>1</output_to_redis></session-report></config></edit-config>
</rpc>
##

```
#### 3.5 enable event report and register the attributes and handlers 
```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<edit-config><target><running/></target><config><event xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><number-of-events>1</number-of-events>
<event-based-reporting>
<event_id>1</event_id><enable>0</enable><condition>ip.src</condition>
<attributes><attr_id>1</attr_id><attr>ip.dst</attr></attributes>
<attributes><attr_id>2</attr_id><attr>ip.version</attr></attributes>
</event-based-reporting></event></config></edit-config></rpc>
##
```
#### 3.6 enable app report (WEB) and register attributes and handlers

```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
<edit-config><target><running/></target><config><session-app-report xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><number-of-app>1</number-of-app>
<app-based-reporting>
<app_id>1</app_id><enable>1</enable><condition>WEB</condition>
<app_attributes><app_attr_id>1</app_attr_id><app_attr>http.method</app_attr><app_attr_handler>http_method_handle</app_attr_handler></app_attributes>
</app-based-reporting></session-app-report></config></edit-config></rpc>
##
```

#### 3.7 enable security2-report, thread count = 1, output to file
```
#512
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><security2-report xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><thread_count>1</thread_count><output_to_file>1</output_to_file></security2-report></config></edit-config>
</rpc>
##
```

#### 3.8 add rules to security
```
#512
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><security2-report xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><add_rules>(1:34,32,33)</add_rules></security2-report></config></edit-config>
</rpc>
##
```
#### 3.9 remove rules from security
```
#512
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><security2-report xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><count_removed_rules>6</count_removed_rules><remove_rules>1-100</remove_rules></security2-report></config></edit-config>
</rpc>
##
```
#### 3.10 copy running config to start-up
```
#512
<rpc message-id="102" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><copy-config><target><startup/></target><source><running/></source></copy-config>
</rpc>
##
```

#### 3.11 enable behavour reporting
```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><behaviour xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><location></location></behaviour></config></edit-config></rpc>
##
```

#### 3.12 enable ftp-reconstruction
```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><ftp-reconstruct xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><location>/opt/mmt/</location></ftp-reconstruct></config></edit-config></rpc>
##
```

#### 3.13 enable micro-flows
```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config><micro-flows xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>0</enable><include_packet_count>0</include_packet_count></micro-flows></config></edit-config></rpc>
##
```
#### 3.14 delete session-report output to redis from the configuration
```
#619
<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><edit-config><target><running/></target><config  xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0"><session-report xmlns="urn:ietf:params:xml:ns:yang:dynamic-mmt-probe"><enable>1</enable><output_to_redis xc:operation="delete"></output_to_redis></session-report></config></edit-config>
</rpc>
##
```