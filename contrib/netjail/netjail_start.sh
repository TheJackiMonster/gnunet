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
    read_topology_string "$filename"
else
    echo read file
    read_topology $filename
fi

shift 2

LOCAL_GROUP="192.168.15"
GLOBAL_GROUP="92.68.150"
KNOWN_GROUP="92.68.151"


echo "Start [local: $LOCAL_GROUP.0/24, global: $GLOBAL_GROUP.0/16]"

netjail_bridge
NETWORK_NET=$RESULT

for X in $(seq $KNOWN); do
	netjail_node
	KNOWN_NODES[$X]=$RESULT
	netjail_node_link_bridge ${KNOWN_NODES[$X]} $NETWORK_NET "$KNOWN_GROUP.$X" 16
	KNOWN_LINKS[$X]=$RESULT
done

declare -A NODES
declare -A NODE_LINKS

for N in $(seq $GLOBAL_N); do
	netjail_node
	ROUTERS[$N]=$RESULT
	netjail_node_link_bridge ${ROUTERS[$N]} $NETWORK_NET "$GLOBAL_GROUP.$N" 16
	NETWORK_LINKS[$N]=$RESULT
	netjail_bridge
	ROUTER_NETS[$N]=$RESULT
	
	for M in $(seq $LOCAL_M); do
		netjail_node
		NODES[$N,$M]=$RESULT
		netjail_node_link_bridge ${NODES[$N,$M]} ${ROUTER_NETS[$N]} "$LOCAL_GROUP.$M" 24
		NODE_LINKS[$N,$M]=$RESULT
	done

	ROUTER_ADDR="$LOCAL_GROUP.$(($LOCAL_M+1))"
	netjail_node_link_bridge ${ROUTERS[$N]} ${ROUTER_NETS[$N]} $ROUTER_ADDR 24
	ROUTER_LINKS[$N]=$RESULT
	
	netjail_node_add_nat ${ROUTERS[$N]} $ROUTER_ADDR 24
	
	for M in $(seq $LOCAL_M); do
		netjail_node_add_default ${NODES[$N,$M]} $ROUTER_ADDR
	done

    # TODO Topology configuration must be enhanced to configure forwarding to more than one subnet node via different ports.
    
    if [ "1" == "${R_TCP[$N]}" ]
    then
        ip netns exec ${ROUTERS[$N]} iptables -t nat -A PREROUTING -p tcp -d $GLOBAL_GROUP.$N --dport 60002 -j DNAT --to $LOCAL_GROUP.1
        ip netns exec ${ROUTERS[$N]} iptables -A FORWARD -d $LOCAL_GROUP.1  -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    fi
    if [ "1" == "${R_UDP[$N]}" ]
    then
        ip netns exec ${ROUTERS[$N]} iptables -t nat -A PREROUTING -p udp -d $GLOBAL_GROUP.$N --dport 60002 -j DNAT --to $LOCAL_GROUP.1
        ip netns exec ${ROUTERS[$N]} iptables -A FORWARD -d $LOCAL_GROUP.1  -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    fi
done
