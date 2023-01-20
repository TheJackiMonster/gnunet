#!/bin/bash

if [ $2 -eq 1 ]
then
    if [ ! -d /tmp/netjail_scripts ]
    then
        mkdir /tmp/netjail_scripts
    fi

    ext_ifname=$(ip addr |grep UP|grep "@"|awk -F: '{printf $2"\n"}'|tr  -d " "|awk -F@ '{printf $1" "}'|awk '{printf $1}')
    listening_ip=$(ip addr |grep UP|grep "@"|awk -F: '{printf $2"\n"}'|tr  -d " "|awk -F@ '{printf $1" "}'|awk '{printf $2}')
    uuid=$(uuidgen)
    cat miniupnpd.conf |sed 's/#ext_ifname=eth1/ext_ifname='$ext_ifname'/g'|sed 's/#listening_ip=eth0/listening_ip='$listening_ip'/g'|sed 's/uuid=73a9cb68-a00b-4d2c-8412-75fc989f0c6/uuid='$uuid'/g'|grep -v "^#"|grep -v '^$' > /tmp/netjail_scripts/gargoyle.txt
    miniupnpd -d -f /tmp/netjail_scripts/gargoyle.txt -P /tmp/netjail_scripts/miniupnpd_$1.pid &
else
    kill $(cat /tmp/netjail_scripts/miniupnpd_$1.pid)
fi





