#!/bin/bash

# This script periodically shows resources used by MMT and lists its output

COMMAND=' echo "-> /opt/mmt/probe/result/report/online    $(ls /opt/mmt/probe/result/report/online | grep csv$ |wc -l) files"'
COMMAND=$COMMAND'; echo "-> /opt/mmt/probe/result/behaviour/online $(ls /opt/mmt/probe/result/behaviour/online | grep csv$ |wc -l) files"'

COMMAND=$COMMAND'; echo "-> pcaps on ram: $(ls /opt/mmt/probe/pcap | grep pcap$ | wc -l) files, on disk: $(du -bs /data/pcap | cut -f1) B"'

#show stats of mmt-bandwith if we can connect to it
if [ $(mongo --eval 'db' --quiet) ]; then
	COMMAND=$COMMAND'; echo "-> mmt-data database"; mongo mmt-data --eval "db.stats(1000*1000)" | head -11 | tail -4'
fi


if [ $(mongo --port 27018 --eval 'db' --quiet) ]; then
    COMMAND=$COMMAND'; echo "-> mmt-bandwidth database"; mongo mmt-bandwidth --port 27018 --eval "db.stats(1000*1000)" | head -11 | tail -4'
fi

COMMAND=$COMMAND'; echo "-> `df -h`" | grep "mmt\|data"'

watch -n 2 "( echo; date; $COMMAND ) | tee -a watch.log"