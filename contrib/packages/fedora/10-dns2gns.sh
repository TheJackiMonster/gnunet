#!/bin/sh
interface=$1
status=$2

if [ "$interface" = "eth0" ]; then
  case $status in
    up)
      if nc -u -z 127.0.0.1 5353; then
        # Note: We add quad 9 here as a fallback in case our service is down.
        resolvectl dns $interface 127.0.0.1:5353 9.9.9.9
      elif
        # Just in case DNS2GNS was already configured, revert to defaults
        resolvectl revert $interface
      fi
    ;;
    down)
    ;;
  esac
fi
