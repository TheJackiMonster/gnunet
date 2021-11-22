#!/bin/bash
string=$(cat << EOF
M:2
N:1
X:0
T:libgnunet_test_transport_plugin_cmd_simple_send
P:1:1|{connect:{P:1:2:tcp}}
P:1:2|{connect:{P:1:1:tcp}}
EOF
      )
if ! [ -d "/run/netns" ]; then
    echo You have to create the directory /run/netns.
fi
if  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" == 1 ]; then
    exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; ./test_transport_start_with_config -s '$string'"
else
    echo -e "Error during test setup: The kernel parameter kernel.unprivileged_userns_clone has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_userns_clone=1\n"
    exit 78
fi
