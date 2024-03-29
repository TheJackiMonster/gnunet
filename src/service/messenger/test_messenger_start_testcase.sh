#!/bin/bash
read -p "Test case configuration to use:" conf
if ! [ -d "/run/netns" ]; then
    echo You have to create the directory /run/netns.
fi
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
  if  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != 1 ]; then
    echo -e "Error during test setup: The kernel parameter kernel.unprivileged_userns_clone has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_userns_clone=1\n"
    exit 78
  fi
fi
START_WITH_CONFIG=/usr/local/lib/gnunet/libexec/test_testing_start_with_config
if [ ! -f /usr/local/lib/gnunet/libexec/test_testing_start_with_config ]; then
  START_WITH_CONFIG=/usr/lib/gnunet/libexec/test_testing_start_with_config
fi
exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; $START_WITH_CONFIG $conf"