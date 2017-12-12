#!/bin/bash

#!/bin/bash
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

sysrepoctl --install --yang=dynamic-mmt.yang --owner=root:root --permission=666
sysrepocfg --import=dynamic-probe.xml --datastore=startup --format=xml dynamic-mmt-probe

screen -S netconf -dm /usr/bin/supervisord -c /opt/dev/sysrepo/deploy/docker/sysrepo-netopeer2/supervisord.conf
