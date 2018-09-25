#!/bin/bash
COMMAND=' echo "-> /opt/mmt/probe/result/report/online    $(ls /opt/mmt/probe/result/report/online | grep csv$ |wc -l) files"'
COMMAND=$COMMAND'; echo "-> /opt/mmt/probe/result/behaviour/online $(ls /opt/mmt/probe/result/behaviour/online | grep csv$ |wc -l) files"'

COMMAND=$COMMAND'; echo -n "-> pcaps on ram: $(ls /opt/mmt/probe/pcap | grep pcap$ | wc -l) files, on disk: " ; du -bs /storage/pcap | cut -f1'

COMMAND=$COMMAND'; echo "-> mmt-data database"; mongo mmt-data --eval "db.stats(1000*1000)" | head -11 | tail -4'
COMMAND=$COMMAND'; echo "-> mmt-bandwidth database"; mongo mmt-bandwidth --eval "db.stats(1000*1000)" | head -11 | tail -4'
COMMAND=$COMMAND'; echo "-> `df -h`" | grep "mmt\|data"'

watch -n 2 "( echo; date; $COMMAND ) | tee -a watch.log"