#!/bin/bash
# This file is in the public domain.

# We will use UDP ports above this number.
MINPORT=10000

# Cleanup to run whenever we exit
function cleanup()
{
    for n in `jobs -p`
    do
        kill $n 2> /dev/null || true
    done
    wait
}

# Install cleanup handler (except for kill -9)
trap cleanup EXIT

if test -z "$1"
then
    echo "Call with the number of peers to launch."
    exit 1
fi

echo -n "Testing for GNU parallel ..."

if test ! -x `which parallel`
then
    echo "This script requires GNU parallel"
    exit 1
fi

parallel -V | grep "GNU parallel" > /dev/null || exit 1

echo " OK"



if test ! -x `which gnunet-service-dht`
then
    echo "This script requires gnunet-service-dht in \$PATH"
    exit 1
fi

if test ! -x `which gnunet-dht-hello`
then
    echo "This script requires gnunet-dht-hello in \$PATH"
    exit 1
fi

MAX=`expr $1 - 1`

export GNUNET_FORCE_LOG="dht*;;;;DEBUG"

echo -n "Starting $1 peers "
mkdir -p /tmp/deployment
for n in `seq 0 $MAX`
do
    PORT=`expr $MINPORT + $n`
    CFG="/tmp/deployment/${n}.conf"
    cat dhtu_testbed_deploy.conf | sed -e "s/%N%/$PORT/" > $CFG
    gnunet-service-dht -c $CFG -L DEBUG &> /tmp/deployment/$n.log &
    echo -n "."
done

echo ""
echo "$1 peers ready".

unset GNUNET_FORCE_LOG

function connect()
{
  n=$1
}

echo -n "Connecting peers ..."

export MAX
if test 0 != $MAX
then
  seq 0 $MAX | parallel ./dhtu_testbed_connect.sh :::
fi


echo ""
echo "Network ready. Press ENTER to terminate the testbed!"
echo "Interact with peers using '-c /tmp/deployment/\$N.conf'"

read

exit 0
