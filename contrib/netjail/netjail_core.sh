#!/bin/sh
# 


PREFIX=${PPID:?must run from a parent process}

# running with `sudo` is required to be
# able running the actual commands as the
# original user.

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

export RESULT=
export NAMESPACE_NUM=0
export INTERFACE_NUM=0

netjail_next_namespace() {
	local NUM=$NAMESPACE_NUM
	NAMESPACE_NUM=$(($NAMESPACE_NUM + 1))
	RESULT=$NUM
}

netjail_next_interface() {
	local NUM=$INTERFACE_NUM
	INTERFACE_NUM=$(($INTERFACE_NUM + 1))
	RESULT=$NUM
}

netjail_opt() {
	local OPT=$1
	shift 1

	INDEX=1

	while [ $# -gt 0 ]; do
		if [ "$1" = "$OPT" ]; then
			RESULT=$INDEX
			return
		fi

		INDEX=$(($INDEX + 1))
		shift 1
	done

	RESULT=0
}

netjail_opts() {
	local OPT=$1
	local DEF=$2
	shift 2
	
	while [ $# -gt 0 ]; do
		if [ "$1" = "$OPT" ]; then
			printf "$2"
			return
		fi

		shift 1
	done
	
	RESULT="$DEF"
}

netjail_check() {
	local NODE_COUNT=$1
	local FD_COUNT=$(($(ls /proc/self/fd | wc -w) - 4))

	# quit if `$FD_COUNT < ($LOCAL_M * $GLOBAL_N * 2)`:
	# the script also requires `sudo -C ($FD_COUNT + 4)`
	# so you need 'Defaults closefrom_override' in the
	# sudoers file.

	if [ $FD_COUNT -lt $(($NODE_COUNT * 2)) ]; then
		echo "File descriptors do not match requirements!" >&2
		exit 1
	fi
}

netjail_check_bin() {
	local PROGRAM=$1
	local MATCH=$(ls $(echo $PATH | tr ":" "\n") | grep "^$PROGRAM\$" | tr "\n" " " | awk '{ print $1 }')

	# quit if the required binary $PROGRAM can not be
	# found in the used $PATH.

	if [ "$MATCH" != "$PROGRAM" ]; then
		echo "Required binary not found: $PROGRAM" >&2
		exit 1
	fi
}

netjail_bridge() {
	netjail_next_interface
	local NUM=$RESULT
	local BRIDGE=$(printf "%06x-%08x" $PREFIX $NUM)

	ip link add $BRIDGE type bridge
	ip link set dev $BRIDGE up
	
	RESULT=$BRIDGE
}

netjail_bridge_name() {
	netjail_next_interface
	local NUM=$RESULT
	local BRIDGE=$(printf "%06x-%08x" $PREFIX $NUM)
	
	RESULT=$BRIDGE
}

netjail_bridge_clear() {
	local BRIDGE=$1

	ip link delete $BRIDGE
}

netjail_node() {
	netjail_next_namespace
	local NUM=$RESULT
	local NODE=$(printf "%06x-%08x" $PREFIX $NUM)

	ip netns add $NODE
	
	RESULT=$NODE
}

netjail_node_name() {
	netjail_next_namespace
	local NUM=$RESULT
	local NODE=$(printf "%06x-%08x" $PREFIX $NUM)
	
	RESULT=$NODE
}

netjail_node_clear() {
	local NODE=$1

	ip netns delete $NODE
}

netjail_node_link_bridge() {
	local NODE=$1
	local BRIDGE=$2
	local ADDRESS=$3
	local MASK=$4
	
	netjail_next_interface
	local NUM_IF=$RESULT
	netjail_next_interface
	local NUM_BR=$RESULT
	
	local LINK_IF=$(printf "%06x-%08x" $PREFIX $NUM_IF)
	local LINK_BR=$(printf "%06x-%08x" $PREFIX $NUM_BR)

	ip link add $LINK_IF type veth peer name $LINK_BR
	ip link set $LINK_IF netns $NODE
	ip link set $LINK_BR master $BRIDGE

	ip -n $NODE addr add "$ADDRESS/$MASK" broadcast + dev $LINK_IF
	ip -n $NODE link set $LINK_IF up
	ip -n $NODE link set up dev lo

	ip link set $LINK_BR up
	
	RESULT=$LINK_BR
}

netjail_node_link_bridge_name() {
	
	netjail_next_interface
	netjail_next_interface
	local NUM_BR=$RESULT
	
	local LINK_BR=$(printf "%06x-%08x" $PREFIX $NUM_BR)
	
	RESULT=$LINK_BR
}

netjail_node_unlink_bridge() {
	local LINK_BR=$1

	ip link delete $LINK_BR
}

netjail_node_add_nat() {
	local NODE=$1
	local ADDRESS=$2
	local MASK=$3

	ip netns exec $NODE iptables -t nat -A POSTROUTING -s "$ADDRESS/$MASK" -j MASQUERADE
}

netjail_node_add_default() {
	local NODE=$1
	local ADDRESS=$2

	ip -n $NODE route add default via $ADDRESS
}

netjail_node_exec() {
    JAILOR=${SUDO_USER:?must run in sudo}
	local NODE=$1
	local FD_IN=$2
	local FD_OUT=$3
	shift 3

	ip netns exec $NODE sudo -u $JAILOR -- $@ 1>& $FD_OUT 0<& $FD_IN
}

netjail_node_exec_without_fds() {
    JAILOR=${SUDO_USER:?must run in sudo}
	NODE=$1
	shift 1

	ip netns exec $NODE sudo -u $JAILOR -- $@
}

netjail_node_exec_without_fds_and_sudo() {
	NODE=$1
	shift 1

	ip netns exec $NODE $@
}

netjail_kill() {
	local PID=$1
	local MATCH=$(ps --pid $PID | awk "{ if ( \$1 == $PID ) { print \$1 } }" | wc -l)

	if [ $MATCH -gt 0 ]; then
		kill -n 19 $PID

		for CHILD in $(ps -o pid,ppid -ax | awk "{ if ( \$2 == $PID ) { print \$1 } }"); do
			netjail_kill $CHILD
		done

		kill $PID
	fi
}

netjail_killall() {
	if [ $# -gt 0 ]; then
		local PIDS=$1

		for PID in $PIDS; do
			netjail_kill $PID
		done
	fi
}

netjail_waitall() {
	if [ $# -gt 0 ]; then
		local PIDS=$1

		for PID in $PIDS; do
			wait $PID
		done
	fi
}

