#!/bin/bash
. "$(dirname $0)/netjail_core.sh"

NODE=$1
shift 1

ip netns exec $NODE $@
#ip netns exec $NODE valgrind --trace-children=yes $@
