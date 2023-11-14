#!/bin/bash
# Computes a simple scalar product, with configurable vector size.
#
# Some results (wall-clock for Alice+Bob, single-core, i7, libgcrypt):
# SIZE   2048-H(s)  2048-O(s)    1024-O(s)      ECC-2^20-H(s)  ECC-2^28-H(s)
#  25     10          14            3              2               29
#  50     17          21            5              2               29
# 100     32          39            7              2               29
# 200                 77           13              3               30
# 400                149           23             OOR              31
# 800                304           32             OOR              33

# Bandwidth (including set intersection):
#              RSA-1024       RSA-2048       ECC
# 800:           629 kb        1234 kb       65 kb
#
# LIBSODIUM, AMD Threadripper 1950:
#
# SIZE              2048-O(s)    1024-O(s)      ECC-2^20-H(s)  ECC-2^28-H(s)
#  25                 4.3          0.7             0.129          4.233
#  50                 7.7          1.2             0.143          4.267
# 100                10.3          2.4             0.163          4.282
# 200                19.8          3.0             0.192          4.326
# 400                35.9          6.0             0.253          4.358
# 800                73.7         12.6             0.379          4.533

#
#
# Configure benchmark size:
SIZE=800
#
# Construct input vectors:
INPUTALICE="-k CCC -e '"
INPUTBOB="-k CCC -e '"
for X in `seq 1 $SIZE`
do
  INPUTALICE="${INPUTALICE}A${X},$X;"
  INPUTBOB="${INPUTBOB}A${X},$X;"
done
INPUTALICE="${INPUTALICE}BC,-20000;RO,1000;FL,100;LOL,24;'"
INPUTBOB="${INPUTBOB}AB,10;RO,3;FL,3;LOL,-1;'"

# necessary to make the testing prefix deterministic, so we can access the config files
PREFIX=/tmp/test-scalarproduct`date +%H%M%S`

# where can we find the peers config files?
CFGALICE="-c $PREFIX/0/config"
CFGBOB="-c $PREFIX/1/config"

# launch two peers in line topology non-interactively
#
# interactive mode would terminate the test immediately
# because the rest of the script is already in stdin,
# thus redirecting stdin does not suffice)
#GNUNET_FORCE_LOG=';;;;ERROR'
#GNUNET_FORCE_LOG='scalarproduct*;;;;DEBUG/cadet-api*;;;;DEBUG'
GNUNET_TESTING_PREFIX=$PREFIX ../testbed/gnunet-testbed-profiler -n -c test_scalarproduct.conf -p 2 &
PID=$!
# sleep 1 is too short on most systems, 2 works on most, 5 seems to be safe
echo "Waiting for peers to start..."
sleep 5
# get Bob's peer ID, necessary for Alice
PEERIDBOB=`gnunet-peerinfo -qs $CFGBOB`

echo "Running problem of size $SIZE"
gnunet-scalarproduct $CFGBOB $INPUTBOB &
time RESULT=`gnunet-scalarproduct $CFGALICE $INPUTALICE -p $PEERIDBOB`
gnunet-statistics $CFGALICE -s core | grep "bytes encrypted"
gnunet-statistics $CFGBOB -s core | grep "bytes encrypted"

echo "Terminating testbed..."
# terminate the testbed
kill $PID
