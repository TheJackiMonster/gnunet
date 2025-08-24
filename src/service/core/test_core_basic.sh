#!/bin/bash
# FIXME
#      this currently works on my (ch3) machine, but is not expected to work on
#      others. It is expecting the netjail testing scripts in a location
#      specific to my machine, because currently they're not available in the
#      build dir
#exec ../../../scripts/netjail/netjail_test_master.sh gnunet-testing-netjail-launcher test_core_basic_topo.conf
exec $GNUNET_PREFIX/../share/gnunet/netjail_test_master.sh gnunet-testing-netjail-launcher test_core_basic_topo.conf
#exec $GNUNET_PREFIX/share/gnunet/netjail_test_master.sh gnunet-testing-netjail-launcher test_core_basic_topo.conf
#exec ../../../scripts/netjail/netjail_test_master.sh 'valgrind --track-origins=yes --log-file=/tmp/core_basic_plugin-%p gnunet-testing-netjail-launcher' test_core_basic_topo.conf
