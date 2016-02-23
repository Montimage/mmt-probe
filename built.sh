#!/bin/bash
sudo gcc -g -o /usr/bin/offlineprobe src/smp_main.c  src/processing.c src/web_session_report.c src/thredis.c src/send_msg_to_file.c src/send_msg_to_redis.c src/rtp_session_report.c src/event_based_reporting.c src/protocols_report.c src/ssl_session_report.c src/default_app_session_report.c src/microflows_session_report.c src/radius_reporting.c src/security_analysis.c src/parseoptions.c src/license.c  src/ftp_session_report.c src/ip_statics.c -lmmt_core -lmmt_tcpip -lmmt_security -lxml2 -ldl -lpcap -lconfuse -lhiredis -lpthread

sudo gcc -g -o /usr/bin/onlineprobe src/smp_main.c  src/processing.c src/web_session_report.c src/thredis.c src/send_msg_to_file.c src/send_msg_to_redis.c src/rtp_session_report.c src/event_based_reporting.c src/protocols_report.c src/ssl_session_report.c src/default_app_session_report.c src/microflows_session_report.c src/radius_reporting.c src/security_analysis.c src/parseoptions.c src/license.c  src/ftp_session_report.c src/ip_statics.c -lmmt_core -lmmt_tcpip -lmmt_security -lxml2 -ldl -lpcap -lconfuse -lhiredis -lpthread

if [ ! -d /temp/ ]
then
    mkdir /temp/
fi
if [ ! -d /temp/reports_online ]
then
    mkdir /temp/reports_online/
fi
if [ ! -d /temp/reports_offline/ ]
then
    mkdir /temp/reports_offline/
fi
if [ ! -d /temp/behaviour_reports_online/ ]
then
    mkdir /temp/behaviour_reports_online/
fi
if [ ! -d /temp/behaviour_reports_offline/ ]
then
    mkdir /temp/behaviour_reports_offline/
fi
if [ ! -d /temp/security_reports_online/ ]
then
    mkdir /temp/security_reports_online/
fi

if [ ! -d /temp/security_reports_offline/ ]
then
    mkdir /temp/security_reports_offline/
fi

if [ ! -d /etc/mmt/ ]
then
    mkdir /etc/mmt/
fi

sudo cp mmt_online.conf /etc/mmt/
sudo cp mmt_offline.conf /etc/mmt/


sudo cp run_mmt_offline /etc/init.d/
sudo cp run_mmt_online /etc/init.d/

sudo chmod +x /etc/init.d/run_mmt_offline
sudo chmod +x /etc/init.d/run_mmt_online




