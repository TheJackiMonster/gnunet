#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup.conf" INT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
TEST_A="139.134.54.9"
MY_EGO="myego"
LABEL="testsbox"
HASH="c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6"
SERVICE_TEXT="_tcp"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$HASH.$SERVICE_TEXT 1 $TEST_A" -e never -c test_gns_lookup.conf
sleep 0.5
RES_A=`$DO_TIMEOUT gnunet-gns --raw -u $HASH.$SERVICE_TEXT.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$HASH.$SERVICE_TEXT 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

if [ "$RES_A" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A, got '$RES_A'."
  exit 1
fi
