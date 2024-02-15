#!/bin/bash
. "$(dirname $0)/netjail_core.sh"
. "$(dirname $0)/topo.sh"

set -eu
set -x

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

filename=$1
PREFIX=$2
readfile=$3

BROADCAST=0

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
# Use the IP addresses below instead of the public ones,
# if the script was not started from within a new namespace
# created by unshare. The UPNP test case needs public IP
# addresse for miniupnpd to function.
# FIXME The ip addresses are used in the c code too. We should
# introduce a switch indicating if public addresses should be
# used or not. This info has to be propagated to the c code.
#GLOBAL_GROUP="172.16.150"
#KNOWN_GROUP="172.16.151"

if [ $BROADCAST -eq 0  ]; then
   PORT="60002"
else
    PORT="2086"
fi

echo "Start [local: $LOCAL_GROUP.0/24, global: $GLOBAL_GROUP.0/16]"

netjail_bridge
NETWORK_NET=$RESULT

IPT=iptables-nft

for X in $(seq $KNOWN); do
	netjail_node
	KNOWN_NODES[$X]=$RESULT
	netjail_node_link_bridge ${KNOWN_NODES[$X]} $NETWORK_NET "$KNOWN_GROUP.$X" 16
	KNOWN_LINKS[$X]=$RESULT

    # Execute echo 1 > /proc/sys/net/netfilter/nf_log_all_netns to make itables log to the host.
    #ip netns exec ${KNOWN_NODES[$X]} $IPT -A INPUT -j LOG --log-prefix '** Known ${KNOWN_NODES[$X]}  **'
    #ip netns exec ${KNOWN_NODES[$X]} $IPT -A OUTPUT -j LOG --log-prefix '** Known ${KNOWN_NODES[$X]}  **'
    ip netns exec ${KNOWN_NODES[$X]} $IPT -A OUTPUT -p icmp -j ACCEPT
    ip netns exec ${KNOWN_NODES[$X]} $IPT -A INPUT -p icmp -j ACCEPT
    
done

declare -A NODES
declare -A NODE_LINKS

for N in $(seq $GLOBAL_N); do
	netjail_node
	ROUTERS[$N]=$RESULT
	netjail_node_link_bridge ${ROUTERS[$N]} $NETWORK_NET "$GLOBAL_GROUP.$N" 16
	ROUTER_EXT_IF[$N]=$RESULT
	netjail_bridge
	ROUTER_NETS[$N]=$RESULT

    #ip netns exec ${ROUTERS[$N]} $IPT -A INPUT -j LOG --log-prefix '** Router ${ROUTERS[$N]}  **'
    ip netns exec ${ROUTERS[$N]} $IPT -A INPUT -p icmp -j ACCEPT
    ip netns exec ${ROUTERS[$N]} $IPT -t nat -A PREROUTING -p icmp -d $GLOBAL_GROUP.$N -j DNAT --to $LOCAL_GROUP.1
    ip netns exec ${ROUTERS[$N]} $IPT -A FORWARD -p icmp -d $LOCAL_GROUP.1  -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    #ip netns exec ${ROUTERS[$N]} $IPT -A OUTPUT -j LOG --log-prefix '** Router ${ROUTERS[$N]}  **'
    ip netns exec ${ROUTERS[$N]} $IPT -A OUTPUT -p icmp -j ACCEPT
    
	for M in $(seq $LOCAL_M); do
		netjail_node
		NODES[$N,$M]=$RESULT
		netjail_node_link_bridge ${NODES[$N,$M]} ${ROUTER_NETS[$N]} "$LOCAL_GROUP.$M" 24
		NODE_LINKS[$N,$M]=$RESULT

        #ip netns exec ${NODES[$N,$M]} $IPT -A INPUT -j LOG --log-prefix '** Node ${NODES[$N,$M]}  **'
        #ip netns exec ${NODES[$N,$M]} $IPT -A OUTPUT -j LOG --log-prefix '** Node ${NODES[$N,$M]}  **'
        ip netns exec ${NODES[$N,$M]} $IPT -A OUTPUT -p icmp -j ACCEPT
        ip netns exec ${NODES[$N,$M]} $IPT -A INPUT -p icmp -j ACCEPT 
	done

	ROUTER_ADDR="$LOCAL_GROUP.$(($LOCAL_M+1))"

    let X=$KNOWN+1
    ip netns exec ${ROUTERS[$N]} ip route add "$KNOWN_GROUP.$X" dev ${ROUTER_EXT_IF[$N]}
    ip netns exec ${ROUTERS[$N]} ip route add default via "$KNOWN_GROUP.$X"


	netjail_node_link_bridge ${ROUTERS[$N]} ${ROUTER_NETS[$N]} $ROUTER_ADDR 24
	ROUTER_LINKS[$N]=$RESULT

	netjail_node_add_nat ${ROUTERS[$N]} $ROUTER_ADDR 24

	for M in $(seq $LOCAL_M); do
		netjail_node_add_default ${NODES[$N,$M]} $ROUTER_ADDR
	done

    # TODO Topology configuration must be enhanced to configure forwarding to more than one subnet node via different ports.

    if [ "1" == "${R_TCP[$N]}" ]
    then
        #ip netns exec ${ROUTERS[$N]} nft add rule ip nat prerouting ip daddr $GLOBAL_GROUP.$N tcp dport 60002 counter dnat to $LOCAL_GROUP.1
        #ip netns exec ${ROUTERS[$N]} nft add rule ip filter FORWARD ip daddr $LOCAL_GROUP.1 ct state new,related,established  counter accept
        if [ "0" == "${R_TCP_ALLOWED_NUMBER[$N]}" ]; then
            ip netns exec ${ROUTERS[$N]} $IPT -t nat -A PREROUTING -p tcp -d $GLOBAL_GROUP.$N --dport 60002 -j DNAT --to $LOCAL_GROUP.1
        else
            delimiter=","
            sources=$GLOBAL_GROUP."${R_TCP_ALLOWED[$N,1,1]}"
            if [ "1" -lt "${R_TCP_ALLOWED_NUMBER[$N]}" ]
            then
               for ((i = 2; i <= ${R_TCP_ALLOWED_NUMBER[$N]}; i++))
               do
                   echo $i
                   temp=$delimiter$GLOBAL_GROUP."${R_TCP_ALLOWED[$N,$i,1]}"
                   sources=$sources$temp
               done
            fi
            echo $sources
            ip netns exec ${ROUTERS[$N]} $IPT -t nat -A PREROUTING -p tcp -s $sources -d $GLOBAL_GROUP.$N --dport 60002 -j DNAT --to $LOCAL_GROUP.1
        fi
        ip netns exec ${ROUTERS[$N]} $IPT -A FORWARD -d $LOCAL_GROUP.1  -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    fi
    if [ "1" == "${R_UDP[$N]}" ]
    then
        #ip netns exec ${ROUTERS[$N]} nft add rule ip nat prerouting ip daddr $GLOBAL_GROUP.$N udp dport $PORT counter dnat to $LOCAL_GROUP.1
        #ip netns exec ${ROUTERS[$N]} nft add rule ip filter FORWARD ip daddr $LOCAL_GROUP.1 ct state new,related,established  counter accept
        if [ "0" == "${R_UDP_ALLOWED_NUMBER[$N]}" ]; then
            ip netns exec ${ROUTERS[$N]} $IPT -t nat -A PREROUTING -p udp -d $GLOBAL_GROUP.$N --dport $PORT -j DNAT --to $LOCAL_GROUP.1
        else
            delimiter=","
            sources=$GLOBAL_GROUP."${R_UDP_ALLOWED[$N,1,1]}"
            if [ "1" -lt "${R_UDP_ALLOWED_NUMBER[$N]}" ]
            then
               for ((i = 2; i <= ${R_UDP_ALLOWED_NUMBER[$N]}; i++))
               do
                   echo $i
                   temp=$delimiter$GLOBAL_GROUP."${R_UDP_ALLOWED[$N,$i,1]}"
                   sources=$sources$temp
               done
            fi
            echo $sources
            ip netns exec ${ROUTERS[$N]} $IPT -t nat -A PREROUTING -p udp -s $GLOBAL_GROUP.$sources -d $GLOBAL_GROUP.$N --dport $PORT -j DNAT --to $LOCAL_GROUP.1
        fi
        ip netns exec ${ROUTERS[$N]} $IPT -A FORWARD -d $LOCAL_GROUP.1  -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    fi
    if [ "" != "${R_SCRIPT[$N]}" ]
    then
        ip netns exec ${ROUTERS[$N]} ./${R_SCRIPT[$N]} ${ROUTER_NETS[$N]} 1 $N &
    fi
done

# We like to have a node acting as a gateway for all router nodes. This is especially needed for sending fake ICMP packets.
netjail_node
GATEWAY=$RESULT
netjail_node_link_bridge $GATEWAY $NETWORK_NET "$KNOWN_GROUP.$X" 16
