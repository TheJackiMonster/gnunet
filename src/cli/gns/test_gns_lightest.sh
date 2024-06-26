#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_gns_lookup.conf" INT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --list-sections 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"
START_EGO="startego"
MY_EGO="test-lightest"
LABEL="test-scheme"
PTR_LABEL="test-ptr"
TEST_URI="10 1 \"https://ec.europa.eu/tools/lotl/eu-lotl.xml\""
TEST_SMIMEA="3 0 1 f7e8e4e554fb7c7a8f6f360e0ca2f59d466c8f9539a25963f5ed37e905f0c797"
SCHEME="_scheme"
TRUST="_trust"
TRANSLATION="_translation"
TEST_PTR="$SCHEME.$TRUST.$LABEL.$MY_EGO.$START_EGO"
TEST_PTR2="$TRANSLATION.$TRUST.$LABEL.$MY_EGO.$START_EGO"
gnunet-arm -s -c test_gns_lookup.conf
gnunet-identity -C $MY_EGO -c test_gns_lookup.conf
gnunet-identity -C $START_EGO -c test_gns_lookup.conf
PKEY=`gnunet-identity -d -e $MY_EGO -q -c test_gns_lookup.conf`
gnunet-namestore -p -z $MY_EGO -a -n $PTR_LABEL -t BOX -V "49152 49152 12 $TEST_PTR" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $PTR_LABEL -t BOX -V "49152 49153 12 $TEST_PTR2" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "49152 49152 256 $TEST_URI" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "49152 49152 53 $TEST_SMIMEA" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "49152 49153 256 $TEST_URI" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "49152 49153 53 $TEST_SMIMEA" -e never -c test_gns_lookup.conf
gnunet-namestore -p -z $START_EGO -a -n $MY_EGO -t PKEY -V "$PKEY" -e never -c test_gns_lookup.conf
sleep 0.5
PTR_SCHEME=`$DO_TIMEOUT gnunet-gns --raw -u $SCHEME.$TRUST.$PTR_LABEL.$MY_EGO.$START_EGO -t PTR -c test_gns_lookup.conf`
PTR_TRANSLATION=`$DO_TIMEOUT gnunet-gns --raw -u $TRANSLATION.$TRUST.$PTR_LABEL.$MY_EGO.$START_EGO -t PTR -c test_gns_lookup.conf`

SUCCESS=0
if [ "$PTR_SCHEME" != "$TEST_PTR" ]
then
  echo "Failed to resolve to proper PTR, got '$PTR_SCHEME'."
  SUCCESS=1
else
  echo "Resolved to proper PTR, got '$PTR_SCHEME'."
fi

if [ "$PTR_TRANSLATION" != "$TEST_PTR2" ]
then
  echo "Failed to resolve to proper PTR, got '$PTR_TRANSLATION'."
  SUCCESS=1
else
  echo "Resolved to proper PTR, got '$PTR_TRANSLATION'."
fi

if [ "$SUCCESS" = "1" ]
then
  gnunet-namestore -z $MY_EGO -X -c test_gns_lookup.conf
  gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
  gnunet-arm -e -c test_gns_lookup.conf
  rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`
  exit 1
fi


RES_URI_SCHEME=`$DO_TIMEOUT gnunet-gns --raw -u $PTR_SCHEME -t URI -c test_gns_lookup.conf`
RES_SMIMEA_SCHEME=`$DO_TIMEOUT gnunet-gns --raw -u $PTR_SCHEME -t SMIMEA -c test_gns_lookup.conf`

RES_URI_TRANSLATION=`$DO_TIMEOUT gnunet-gns --raw -u $PTR_TRANSLATION -t URI -c test_gns_lookup.conf`
RES_SMIMEA_TRANSLATION=`$DO_TIMEOUT gnunet-gns --raw -u $PTR_TRANSLATION -t SMIMEA -c test_gns_lookup.conf`


if [ "$RES_URI_SCHEME" != "$TEST_URI" ]
then
  echo "Failed to resolve to proper URI, got '$RES_URI_SCHEME'."
  SUCCESS=1
else
  echo "Resolved to proper URI, got '$RES_URI_SCHEME'."
fi

if [ "$RES_SMIMEA_SCHEME" != "$TEST_SMIMEA" ]
then
  echo "Failed to resolve to proper SMIMEA, got '$RES_SMIMEA_SCHEME'."
  SUCCESS=1
else
  echo "Resolved to proper SMIMEA, got '$RES_SMIMEA_SCHEME'."
fi

if [ "$RES_URI_TRANSLATION" != "$TEST_URI" ]
then
  echo "Failed to resolve to proper URI, got '$RES_URI_TRANSLATION'."
  SUCCESS=1
else
  echo "Resolved to proper URI, got '$RES_URI_TRANSLATION'."
fi

if [ "$RES_SMIMEA_TRANSLATION" != "$TEST_SMIMEA" ]
then
  echo "Failed to resolve to proper SMIMEA, got '$RES_SMIMEA_TRANSLATION'."
  SUCCESS=1
else
  echo "Resolved to proper SMIMEA, got '$RES_SMIMEA_TRANSLATION'."
fi

gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "49152 49152 256 10 1 \"thisisnotavaliduri\"" -e never -c test_gns_lookup.conf
status=$?
gnunet-namestore -p -z $MY_EGO -a -n $LABEL -t BOX -V "49152 49152 256 10 1 mailto:thisrecordismalformed@test.com" -e never -c test_gns_lookup.conf
status2=$?

if [ "$status" = "0" ]
then
  echo "Failed to detect malformed URI."
  SUCCESS=1
else
  echo "Detected malformed URI."
fi

if [ "$status2" = "0" ]
then
  echo "Failed to detect malformed URI Record Presentation."
  SUCCESS=1
else
  echo "Detected malformed URI Presentation."
fi



gnunet-namestore -z $MY_EGO -X -c test_gns_lookup.conf
gnunet-namestore -z $START_EGO -X -c test_gns_lookup.conf
gnunet-identity -D $MY_EGO -c test_gns_lookup.conf
gnunet-identity -D $START_EGO -c test_gns_lookup.conf
gnunet-arm -e -c test_gns_lookup.conf
rm -rf `gnunet-config -c test_gns_lookup.conf -f -s paths -o GNUNET_TEST_HOME`

exit $SUCCESS