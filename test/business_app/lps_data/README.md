
# 1. Download, compile, and install the lastest version of mmt-sdk, and mmt-security

- MMT-SDK
    + branch `proto-s1ap`

- MMT-Security
    + branch `5greplay`
    + Build: `make clean-all; make DEBUG=1; sudo make install`

# 2. Download and compile mmt-probe

- Code info:
    + branch `replay`

- Compile MMT-Probe: `make clean; make DEBUG STREAM_CAPTURE SECURITY_MODULE compile`



# 3. Execution

## 3.1 List all atributes of IPS_DATA

- See `attributes` in `ips_data` block of [mmt-probe.conf](./mmt-probe.conf)

- Run MMT-Probe: `sudo ./probe -c test/business_app/ips_data/mmt-probe.conf`

- See .csv files in `/opt/mmt/probe/result/report/online/`, e.g., run this command `grep "ips_data" /opt/mmt/probe/result/report/online/* | more`
to list all reports of the `ips_data` event-based report.



## 3.2 Security verification

- See an example in [lps-data-rules.xml](./lps-data-rules.xml)

- Compile the example rule: `mkdir rules; /opt/mmt/security/bin/compile_rule rules/ips-data-rules.so test/business_app/ips_data/ips-data-rules.xml`

- Run MMT-Probe: `sudo ./probe -c test/business_app/ips_data/mmt-probe.conf -Xsecurity.enable=true`
