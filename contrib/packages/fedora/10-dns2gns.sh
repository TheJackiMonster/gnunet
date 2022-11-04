#!/bin/bash
interface=$1
status=$2

do_it=$(gnunet-config -s dns2gns -o ENABLE_RESOLVECTL_NMDISPATCHER -c /etc/gnunet.conf)
if [ $? != 0 ]; then
  exit 1
fi
if [ $do_it = "NO" ]; then
  echo "Setting DNS2GNS through resolvectl disabled."
  exit 1
fi

case $status in
  up)
    if nc -u -z 127.0.0.1 5353; then
      # Note: We add quad 9 as a fallback in case our service is down.
      dns2gns=$(gnunet-config -s dns2gns -o BIND_TO)
      if [ $? != 0 ]; then
        exit 1
      fi
      dns2gns6=$(gnunet-config -s dns2gns -o BIND_TO6)
      if [ $? != 0 ]; then
        exit 1
      fi
      port=$(gnunet-config -s dns2gns -o PORT)
      if [ $? != 0 ]; then
        exit 1
      fi
      olddns=$(resolvectl status $interface | grep "DNS Servers" | cut -d':' -f2-)
      if [ $? == 0 ]; then
        #echo "Setting to $dns2gns:$port [$dns2gns6]:$port $olddns 9.9.9.9"
        #resolvectl dns $interface $dns2gns:$port [$dns2gns6]:$port $olddns 9.9.9.9
        echo "Setting to $dns2gns:$port [$dns2gns6]:$port"
        resolvectl dns $interface $dns2gns:$port [$dns2gns6]:$port
      else
        exit 1
      fi
    fi
  ;;
  down)
  ;;
esac
