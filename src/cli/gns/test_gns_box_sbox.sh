#!/bin/bash
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
TEST_B="TXT_record_in_BOX"
TEST_S="TXT_record_in_SBOX"
TEST_A="10.1.11.10"
MY_EGO="myego"
LABEL="testsbox"
SERVICE="443"
SERVICE_TEXT="_443"
PROTOCOL="6"
PROTOCOL_TEXT="_tcp"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$SERVICE_TEXT.$PROTOCOL_TEXT 16 $TEST_S" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "$PROTOCOL $SERVICE 16 $TEST_B" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t SBOX -V "$SERVICE_TEXT.$PROTOCOL_TEXT 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "$PROTOCOL $SERVICE 1 $TEST_A" -e never -c test_gns_lookup.conf
sleep 0.5
RES_B_S=`$DO_TIMEOUT gnunet-gns --raw -u $SERVICE_TEXT.$PROTOCOL_TEXT.$LABEL.$MY_EGO -t TXT -c test_gns_lookup.conf`
RES_A=`$DO_TIMEOUT gnunet-gns --raw -u $SERVICE_TEXT.$PROTOCOL_TEXT.$LABEL.$MY_EGO -t A -c test_gns_lookup.conf`
gnunet-namestore -z $MY_EGO -d -n $LABEL -t SBOX -V "$SERVICE_TEXT.$PROTOCOL_TEXT 16 $TEST_S" -e never -c test_gns_lookup.conf
gnunet-namestore -z $MY_EGO -d -n $LABEL -t BOX -V "$PROTOCOL $SERVICE 16 $TEST_B" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -d -n $LABEL -t SBOX -V "$SERVICE_TEXT.$PROTOCOL_TEXT 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -d -n $LABEL -t BOX -V "$PROTOCOL $SERVICE 1 $TEST_A" -e never -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

{ read RES_A1; read RES_A2; read RES_B; read RES_S;} <<< "${RES_B_S}"
if [ "$RES_B" = "$RES_S" ]
then
  echo "Failed to resolve to diffrent TXT records, got '$RES_B' and '$RES_S'."
  exit 1
fi

{ read RES_S_A; read RES_B_A;} <<< "${RES_A}"
if [ "$RES_S_A" = "$TEST_A" ] && [ "$RES_B_A" = "$TEST_A" ]
then
  exit 0
else
  echo "Failed to resolve to proper A '$TEST_A', got '$RES_S_A' and '$RES_S_B'."
  exit 1
fi
