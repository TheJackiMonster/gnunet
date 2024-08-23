#!/bin/bash
. "$(dirname $0)/netjail_core.sh"
echo gaga
set -u
set -x

filename=$1

PREFIX=$2
readfile=$3

echo gaga
if [ $readfile -eq 0 ]
then
    cmd='gnunet-config -n '
    option=' -R '
else
    echo read file
    cmd='gnunet-config -n '
    option=' -c '
fi
echo cmd $cmd
# The order in which the namespaces of the topology are created must be in sync with the order the topology file is parsed in the C code. 

configure_subnet_peer()
{
    X=$1
    Y=$2
    echo subnet peers $X $Y
    for Z in $(seq ${CARRIER_SUBNET_PEERS[$X,$Y]}); do

        echo gaga 5
        TOTAL_NODES=$(($TOTAL_NODES+1))

        SETUP_PROGRAMMS=$($cmd-s CARRIER-$X-SUBNET-$Y-PEER-$Z -o SETUP_PROGRAMMS$option"$filename")
        if [ -n "$SETUP_PROGRAMMS" ]
        then
            CARRIER_SUBNET_PEER_SETUP_PROGRAMMS[$X,$Y,$Z]=$SETUP_PROGRAMMS
        else
            CARRIER_SUBNET_PEER_SETUP_PROGRAMMS[$X,$Y,$Z]=$PEER_SETUP_PROGRAMMS
        fi
        CARRIER_SUBNET_PEER_TESTBED_PLUGIN=$($cmd-s CARRIER-$X-SUBNET-$Y-PEER-$Z -o TESTBED_PLUGIN$option"$filename")
        if [ -n "$CARRIER_SUBNET_PEER_TESTBED_PLUGIN" ]
        then
            CARRIER_SUBNET_PEER_TESTBED_PLUGIN[$X,$Y,Z]=$CARRIER_SUBNET_PEER_TESTBED_PLUGIN
        else
            CARRIER_SUBNET_PEER_TESTBED_PLUGIN[$X,$Y,Z]=$DEFAULT_TESTBED_PLUGIN
        fi

        ADDRESS=${CARRIER_NET/X/$X}
        ADDRESS=${ADDRESS/Y/$Y}
        ADDRESS=${ADDRESS/Z/$Z}
        netjail_node
	    SUBNET_PEER[$X,$Y,$Z]=$RESULT
		netjail_node_link_bridge ${SUBNET_PEER[$X,$Y,$Z]} ${SUBNET_ROUTER_NETS[$X,$Y]} $ADDRESS 24
    done
}

configure_carrier_subnet()
{
    X=$1

    netjail_bridge
    CARRIER_BRIDGE=$RESULT

    for Y in $(seq ${CARRIER_SUBNETS[$X]}); do

        echo gaga 4
        TOTAL_NODES=$(($TOTAL_NODES+1))

        SETUP_PROGRAMMS=$($cmd-s CARRIER-$X-SUBNET-$Y -o SETUP_PROGRAMMS$option"$filename")
        if [ -n "$SETUP_PROGRAMMS" ]
        then
            CARRIER_SUBNET_SETUP_PROGRAMMS[$X,$Y]=$SETUP_PROGRAMMS
        else
            CARRIER_SUBNET_SETUP_PROGRAMMS[$X,$Y]=$SUBNET_SETUP_PROGRAMMS
        fi
        echo subnets $Y
        CARRIER_SUBNET=$($cmd-s CARRIER-$X-SUBNET-$Y -o SUBNET$option"$filename")
        if [ -n "$CARRIER_SUBNET" ]
        then
            CARRIER_SUBNET[$X,$Y]=$CARRIER_SUBNET
        else
            CARRIER_SUBNET[$X,$Y]=$DEFAULT_CARRIER_SUBNET
        fi
        CARRIER_SUBNET_PEERS=$($cmd-s CARRIER-$X-SUBNET-$Y -o SUBNET_PEERS$option"$filename")
        if [ -n "$CARRIER_SUBNET_PEERS" ]
        then
            CARRIER_SUBNET_PEERS[$X,$Y]=$CARRIER_SUBNET_PEERS
        else
            CARRIER_SUBNET_PEERS[$X,$Y]=$DEFAULT_SUBNET_PEERS
        fi
        CARRIER_SUBNET_TESTBED_PLUGIN=$($cmd-s CARRIER-$X-SUBNET-$Y -o TESTBED_PLUGIN$option"$filename")
        if [ -n "$CARRIER_SUBNET_TESTBED_PLUGIN" ]
        then
            CARRIER_SUBNET_TESTBED_PLUGIN[$X,$Y]=$CARRIER_SUBNET_TESTBED_PLUGIN
        else
            CARRIER_SUBNET_TESTBED_PLUGIN[$X,$Y]=$DEFAULT_TESTBED_PLUGIN
        fi

        SUBNET_NODE_NUMBER[$X]=$((${CARRIER_PEERS[$X]}+$Y))
        ADDRESS=${CARRIER_NET/X/$X}
        ADDRESS=${ADDRESS/Y/${SUBNET_NODE_NUMBER[$X]}}
        ADDRESS=${ADDRESS/Z/0}
        netjail_node
	    SUBNET_ROUTERS[$X,$Y]=$RESULT
	    netjail_node_link_bridge ${SUBNET_ROUTERS[$X,$Y]} ${CARRIER_ROUTER_NETS[$X]} $ADDRESS 16
	    SUBNET_ROUTER_EXT_IF[$X,$Y]=$RESULT
	    netjail_bridge
	    SUBNET_ROUTER_NETS[$X,$Y]=$RESULT

        configure_subnet_peer $X $Y

        echo gaga 5.5 ${SUBNET_ROUTERS[$X,$Y]}

        ROUTER_ADDRESS=${CARRIER_NET/X/$X}
        ROUTER_ADDRESS=${ROUTER_ADDRESS/Y/$((${CARRIER_SUBNETS[$X]}+1))}
        ROUTER_ADDRESS=${ROUTER_ADDRESS/Z/0}

        ip netns exec ${SUBNET_ROUTERS[$X,$Y]} ip route add $ROUTER_ADDRESS dev ${SUBNET_ROUTER_EXT_IF[$X,$Y]}
        ip netns exec ${SUBNET_ROUTERS[$X,$Y]} ip route add default via $ROUTER_ADDRESS
        ip netns exec ${SUBNET_ROUTERS[$X,$Y]} sleep 2000 &

        ADDRESS=${CARRIER_NET/X/$X}
        ADDRESS=${ADDRESS/Y/${SUBNET_NODE_NUMBER[$X]}}
        ADDRESS=${ADDRESS/Z/$((${CARRIER_SUBNET_PEERS[$X,$Y]}+1))}

        netjail_node_link_bridge ${SUBNET_ROUTERS[$X,$Y]} ${SUBNET_ROUTER_NETS[$X,$Y]} $ADDRESS 24

        netjail_node_add_nat ${SUBNET_ROUTERS[$X,$Y]} $ADDRESS 24

        for Z in $(seq ${CARRIER_SUBNET_PEERS[$X,$Y]}); do
		    netjail_node_add_default ${SUBNET_PEER[$X,$Y,$Z]} $ADDRESS
	    done
        echo gaga 6
    done
}

configure_carrier_peer()
{
    X=$1
    for Y in $(seq ${CARRIER_PEERS[$X]}); do

        echo gaga 3
        TOTAL_NODES=$(($TOTAL_NODES+1))

        CARRIER_PEER_TESTBED_PLUGIN=$($cmd-s CARRIER-$X-PEER-$Y -o TESTBED_PLUGIN$option"$filename")
        if [ -n "$CARRIER_PEER_TESTBED_PLUGIN" ]
        then
            CARRIER_PEER_TESTBED_PLUGIN[$X,$Y]=$CARRIER_PEER_TESTBED_PLUGIN
        else
            CARRIER_PEER_TESTBED_PLUGIN[$X,$Y]=$DEFAULT_TESTBED_PLUGIN
        fi
        ADDRESS=${CARRIER_NET/X/$X}
        ADDRESS=${ADDRESS/Y/$Y}
        ADDRESS=${ADDRESS/Z/0}
        netjail_node
		CARRIER_PEER[$X,$Y]=$RESULT
		netjail_node_link_bridge ${CARRIER_PEER[$X,$Y]} ${CARRIER_ROUTER_NETS[$X]} $ADDRESS 16
    done
}

configure_carriers ()
{
    X=$1

    SETUP_PROGRAMMS=$($cmd-s CARRIER-$X -o SETUP_PROGRAMMS$option"$filename")
    if [ -n "$SETUP_PROGRAMMS" ]
    then
        CARRIER_SETUP_PROGRAMMS[$X]=$SETUP_PROGRAMMS
    else
        CARRIER_SETUP_PROGRAMMS[$X]=$CARRIER_SETUP_PROGRAMMS[0]
    fi
    SUBNET=$($cmd-s CARRIER-$X -o SUBNET$option"$filename")
    if [ -n "$SUBNET" ]
    then
        SUBNET[$X]=$SUBNET
    else
        SUBNET[$X]=$DEFAULT_SUBNET
    fi
    CARRIER_TESTBED_PLUGIN=$($cmd-s CARRIER-$X -o TESTBED_PLUGIN$option"$filename")
    if [ -n "$CARRIER_TESTBED_PLUGIN" ]
    then
        CARRIER_TESTBED_PLUGIN[$X]=$CARRIER_TESTBED_PLUGIN
    else
        CARRIER_TESTBED_PLUGIN[$X]=$DEFAULT_TESTBED_PLUGIN
    fi
    CARRIER_PEERS=$($cmd-s CARRIER-$X -o CARRIER_PEERS$option"$filename")
    if [ -n "$CARRIER_PEERS" ]
    then
        CARRIER_PEERS[$X]=$CARRIER_PEERS
    else
        CARRIER_PEERS[$X]=$DEFAULT_CARRIER_PEERS
    fi
    CARRIER_SUBNETS=$($cmd-s CARRIER-$X -o SUBNETS$option"$filename")
    if [ -n "$CARRIER_SUBNETS" ]
    then
        CARRIER_SUBNETS[$X]=$CARRIER_SUBNETS
    else
        CARRIER_SUBNETS[$X]=$DEFAULT_SUBNETS
    fi
    # FIXME configure backbone peers

    echo gaga 2
    ADDRESS=${INET/X/$(($BACKBONE_PEERS+$X))}
    netjail_node
	CARRIER_ROUTERS[$X]=$RESULT
	netjail_node_link_bridge ${CARRIER_ROUTERS[$X]} $NETWORK_NET $ADDRESS 16
    CARRIER_ROUTER_EXT_IF[$X]=$RESULT
	netjail_bridge
	CARRIER_ROUTER_NETS[$X]=$RESULT

    configure_carrier_peer $X
    configure_carrier_subnet $X

    echo gaga 7 ${CARRIER_PEERS[$X]}

    ADDRESS=${INET/X/$XX}
    ip netns exec ${CARRIER_ROUTERS[$X]} ip route add $ADDRESS dev ${CARRIER_ROUTER_EXT_IF[$X]}
    ip netns exec ${CARRIER_ROUTERS[$X]} ip route add default via $ADDRESS
    ip netns exec ${CARRIER_ROUTERS[$X]} sleep 2001 &

    ROUTER_ADDRESS=${CARRIER_NET/X/$X}
    ROUTER_ADDRESS=${ROUTER_ADDRESS/Y/$((${CARRIER_SUBNETS[$X]}+1))}
    ROUTER_ADDRESS=${ROUTER_ADDRESS/Z/0}

    netjail_node_link_bridge ${CARRIER_ROUTERS[$X]} ${CARRIER_ROUTER_NETS[$X]} $ROUTER_ADDRESS 16

    netjail_node_add_nat ${CARRIER_ROUTERS[$X]} $ROUTER_ADDRESS 16

    for Y in $(seq ${CARRIER_PEERS[$X]}); do
		netjail_node_add_default ${CARRIER_PEER[$X,$Y]} $ROUTER_ADDRESS
	done
    echo gaga 7.5
    for Y in $(seq ${CARRIER_SUBNETS[$X]}); do
		netjail_node_add_default ${SUBNET_ROUTERS[$X,$Y]} $ROUTER_ADDRESS
	done
    echo gaga 8
}

DEFAULT_SUBNET=10.X.0.0
DEFAULT_CARRIER_SUBNET=10.X.Y.0

INET=192.168.1.X
CARRIER_NET=10.X.Y.Z


CARRIER_SETUP_PROGRAMMS[0]=$($cmd-s DEFAULTs -o CARRIER_SETUP_PROGRAMMS$option"$filename")
SUBNET_SETUP_PROGRAMMS=$($cmd-s DEFAULTs -o SUBNET_SETUP_PROGRAMMS$option"$filename")
PEER_SETUP_PROGRAMMS[0]=$($cmd-s DEFAULTs -o PEER_SETUP_PROGRAMMS$option"$filename")
DEFAULT_SUBNETS=$($cmd-s DEFAULTs -o SUBNETS$option"$filename")
DEFAULT_TESTBED_PLUGIN=$($cmd-s DEFAULTs -o TESTBED_PLUGIN$option"$filename")
DEFAULT_CARRIER_PEERS=$($cmd-s DEFAULTs -o CARRIER_PEERS$option"$filename")
DEFAULT_SUBNET_PEERS=$($cmd-s DEFAULTs -o SUBNET_PEERS$option"$filename")
BACKBONE_PEERS=$($cmd-s BACKBONE -o BACKBONE_PEERS$option"$filename")
CARRIERS=$($cmd-s BACKBONE -o CARRIERS$option"$filename")

TOTAL_NODES=0

netjail_bridge
NETWORK_NET=$RESULT

echo gaga 1 $BACKBONE_PEERS

for X in $(seq $BACKBONE_PEERS); do
    echo gaga 1.1
    TOTAL_NODES=$(($TOTAL_NODES+1))
    BACKBONE_PEER_TESTBED_PLUGIN=$($cmd-s BACKBONE-PEER-$X -o TESTBED_PLUGIN$option"$filename")
    if [ -n "$BACKBONE_PEER_TESTBED_PLUGIN" ]
    then
        BACKBONE_PEER_TESTBED_PLUGIN[$X]=$BACKBONE_PEER_TESTBED_PLUGIN
    else
        BACKBONE_PEER_TESTBED_PLUGIN[$X]=$DEFAULT_TESTBED_PLUGIN
    fi
    # FIXME configure backbone peers

    echo gaga 0 $BACKBONE_PEER_TESTBED_PLUGIN
    netjail_node
	BB_PEERS[$X]=$RESULT
    ADDRESS=${INET/X/$X}
	netjail_node_link_bridge ${BB_PEERS[$X]} $NETWORK_NET $ADDRESS  16
done

IPT=iptables-nft

let XX=$BACKBONE_PEERS+$CARRIERS+1

for X in $(seq $CARRIERS); do
    TOTAL_NODES=$(($TOTAL_NODES+1))
    configure_carriers $X
done

netjail_node
GATEWAY=$RESULT
ADDRESS=${INET/X/$XX}
netjail_node_link_bridge $GATEWAY $NETWORK_NET $ADDRESS 16

