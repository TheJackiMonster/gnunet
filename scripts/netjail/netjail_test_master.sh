#!/bin/bash
if ! [ -d "/run/netns" ];
then
    echo "You have to create the directory '/run/netns'."
    exit 77
fi
#if [ -f /proc/sys/kernel/unprivileged_userns_clone ];
#then
#    if [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != 1 ];
#    then
#        echo -e "Error during test setup: The kernel parameter 'kernel.unprivileged_us#erns_clone' has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_user#ns_clone=1\n"
#        exit 77
#    fi
#else
#    echo -e "Error during test setup: The kernel lacks the parameter 'kernel.unprivile#ged_userns_clone'\n"
#    exit 77
#fi
exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; $*"
