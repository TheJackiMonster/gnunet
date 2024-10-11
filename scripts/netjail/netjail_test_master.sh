#!/bin/bash
if ! [ -d "/run/netns" ];
then
    echo "You have to create the directory '/run/netns'."
    exit 77
fi
if [ -f /proc/sys/kernel/unprivileged_userns_clone ];
then
    if [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != "1" ];
    then
        echo -e "Error during test setup: The kernel parameter 'kernel.unprivileged_userns_clone' has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_userns_clone=1\n"
        exit 77
    fi
else
    echo -e "Error during test setup: The kernel lacks the parameter 'kernel.unprivileged_userns_clone'\n"
    exit 77
fi
if [ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ];
then
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" != "0" ];
    then
        echo -e "Error during test setup: The kernel parameter 'kernel.apparmor_restrict_unprivileged_userns' has to be set to 0! One has to execute\n\n sysctl kernel.apparmor_restrict_unprivileged_userns=0\n"
        exit 77
    fi
fi
exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; $*"
#exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; G_SLICE=always_malloc DEBUGINFOD_URLS="https://debuginfod.archlinux.org" valgrind --track-origins=yes $*"
