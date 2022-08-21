#!/bin/bash
# This file is in the public domain.

set -eu

# Helper script for dhtu_testbed_deploy.sh.
# Do not invoke directly.

n=$1
CFG="/tmp/deployment/${n}.conf"
HELLO=`gnunet-dht-hello -c $CFG`

# Create dense topology:
#for OFF in `seq 1 $MAX`
#do
#    TCFG="/tmp/deployment/${OFF}.conf"
#    gnunet-dht-hello -c $TCFG $HELLO
#done
#exit 0

# Create sparse topology:
R=1
while test `expr $R \* $R \* $R` -lt $MAX
do
    END=`expr $R \* $R`
    for M in `seq $R $R $END`
    do
        OFF=`expr \( $n + $M \) % $MAX`
        TCFG="/tmp/deployment/${OFF}.conf"
        gnunet-dht-hello -c $TCFG $HELLO
    done
    R=`expr $R + 1`
done
