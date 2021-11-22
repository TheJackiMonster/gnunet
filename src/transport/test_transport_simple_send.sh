#!/bin/bash
if ! [ -d "/run/netns" ]; then
    echo You have to create the directory /run/netns.
fi
if  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" == 1 ]; then
    exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; ./test_transport_start_with_config test_transport_simple_send_topo.conf"
else
    echo -e "Error during test setup: The kernel parameter kernel.unprivileged_userns_clone has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_userns_clone=1\n"
    exit 78
fi
