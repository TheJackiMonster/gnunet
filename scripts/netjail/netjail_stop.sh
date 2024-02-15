#!/bin/bash
. "$(dirname $0)/netjail_core.sh"
. "$(dirname $0)/topo.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

filename=$1
PREFIX=$2
readfile=$3

if [ $readfile -eq 0 ]
then
    read_topology_string $filename
else
    read_topology $filename
fi

declare -A NODES
declare -A NODE_LINKS

netjail_bridge_name
NETWORK_NET=$RESULT

for X in $(seq $KNOWN); do
    netjail_node_name
	KNOWN_NODES[$X]=$RESULT
    netjail_node_link_bridge_name
    KNOWN_LINKS[$X]=$RESULT
    netjail_node_unlink_bridge ${KNOWN_LINKS[$X]}
	netjail_node_clear ${KNOWN_NODES[$X]}
done

for N in $(seq $GLOBAL_N); do
    netjail_node_name
	ROUTERS[$N]=$RESULT
    netjail_node_link_bridge_name
    NETWORK_LINKS[$N]=$RESULT
    netjail_bridge_name
    ROUTER_NETS[$N]=$RESULT
    netjail_node_link_bridge_name
    ROUTER_LINKS[$N]=$RESULT

    if [ -d /tmp/netjail_scripts ]
    then
        if [ "" != "${R_SCRIPT[$N]}" ]
        then
            ip netns exec ${ROUTERS[$N]} ./${R_SCRIPT[$N]} ${ROUTERS[$N]} 0 $N
        fi    
        rm -rf /tmp/netjail_scripts
    fi

    netjail_node_unlink_bridge ${ROUTER_LINKS[$N]}
    
	for M in $(seq $LOCAL_M); do
        netjail_node_name
		NODES[$N,$M]=$RESULT
        netjail_node_link_bridge_name
        NODE_LINKS[$N,$M]=$RESULT
		netjail_node_unlink_bridge ${NODE_LINKS[$N,$M]}
		netjail_node_clear ${NODES[$N,$M]}
	done

	
	netjail_bridge_clear ${ROUTER_NETS[$N]}
	netjail_node_unlink_bridge ${NETWORK_LINKS[$N]}
	netjail_node_clear ${ROUTERS[$N]}
done

netjail_bridge_clear $NETWORK_NET

echo "Done"
