#!/bin/bash
if [ -f "test.out" ]; then
    rm test.out
fi
if ! [ -d "/run/netns" ]; then
    echo You have to create the directory /run/netns.
fi
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
  if  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != 1 ]; then
    echo -e "Error during test setup: The kernel parameter kernel.unprivileged_userns_clone has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_userns_clone=1\n"
    exit 78
  fi
fi
exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; GNUNET_FORCE_LOG=';;;;DEBUG' GNUNET_FORCE_LOGFILE='test.out' ./test_transport_start_with_config test_transport_udp_backchannel_topo.conf"
