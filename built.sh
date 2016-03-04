#!/bin/bash

if [ ! -d /opt ]
then
    sudo mkdir /opt/
fi

if [ ! -d /opt/mmt/ ]
then
    sudo mkdir /opt/mmt/
fi


if [ -z "$1" ]
then
output_dir="/opt/mmt/"
echo "Output directory /opt/mmt/"
else
if [ ! -d $1 ]
then
echo "Created $1"
sudo mkdir -p $1
output_dir="$1"
else
output_dir="$1"
echo "Already exists $1"
fi
fi

if [ ! -d $output_dir/mmt_results/ ]
then
    sudo mkdir $output_dir/mmt_results/
fi

if [ ! -d $output_dir/mmt_results/reports_online/ ]
then
    sudo mkdir $output_dir/mmt_results/reports_online/
fi

if [ ! -d $output_dir/mmt_results/reports_offline/ ]
then
    sudo mkdir $output_dir/mmt_results/reports_offline/
fi

if [ ! -d $output_dir/mmt_results/behaviour_reports_online/ ]
then
    sudo mkdir $output_dir/mmt_results/behaviour_reports_online/
fi

if [ ! -d $output_dir/mmt_results/behaviour_reports_offline/ ]
then
    sudo mkdir $output_dir/mmt_results/behaviour_reports_offline/
fi

if [ ! -d $output_dir/mmt_results/security_reports_online/ ]
then
    sudo mkdir $output_dir/mmt_results/security_reports_online/
fi

if [ ! -d $output_dir/mmt_results/security_reports_offline/ ]
then
    sudo mkdir $output_dir/mmt_results/security_reports_offline/
fi

if [ ! -d $output_dir/mmt_conf/ ]
then
    sudo mkdir $output_dir/mmt_conf/
fi

if [ ! -d $output_dir/mmt_bin/ ]
then
    sudo mkdir $output_dir/mmt_bin/
fi

if [ ! -d $output_dir/mmt_log/ ]
then
    sudo mkdir $output_dir/mmt_log/
fi

if [ ! -f log.data ]
then
    touch $output_dir/mmt_log/log.data
fi

var="/opt/"

#sudo sed "s|$var|$output_dir|g" mmt_offline.conf > $output_dir/mmt_conf/mmt_offline.conf
sudo sed "s|$var|$output_dir|g" mmt_online.conf > $output_dir/mmt_conf/mmt_online.conf



#sudo cp log.data $output_dir/mmt_log/
sudo cp onlineprobe $output_dir/mmt_bin/
sudo cp offlineprobe $output_dir/mmt_bin/
#sudo sed "s|$var|$output_dir|g" conf_offline_probe > /etc/init.d/run_mmt_offline
sudo sed "s|$var|$output_dir|g" conf_online_probe > /etc/init.d/run_mmt_online

sudo cp License_key.key $output_dir/mmt_bin/

sudo chmod +x /etc/init.d/run_mmt_online
sudo chmod +x /etc/init.d/run_mmt_offline






