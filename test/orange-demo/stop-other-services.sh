#!/bin/bash
#if [ "$(id -u)" != "0" ]; then
#   echo "This script must be run as root" 1>&2
#   exit 1
#fi

#who is using this?
sudo service php7.0-fpm stop
#sudo service postgresql stop
sudo service redis-server stop
sudo service snapd stop