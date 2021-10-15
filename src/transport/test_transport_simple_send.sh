#!/bin/bash
exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; ./test_transport_start_with_config test_transport_simple_send_topo.conf"
