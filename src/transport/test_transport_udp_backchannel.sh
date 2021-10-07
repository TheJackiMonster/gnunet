#!/bin/bash
#exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; valgrind --leak-check=full --track-origins=yes --trace-children=yes --trace-children-skip=/usr/bin/awk,/usr/bin/cut,/usr/bin/seq,/sbin/ip ./test_transport_start_with_config test_transport_udp_backchannel_topo.conf"
exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; ./test_transport_start_with_config test_transport_udp_backchannel_topo.conf"
# exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; valgrind --leak-check=full --track-origins=yes ./test_transport_start_with_config test_transport_udp_backchannel_topo.conf"
