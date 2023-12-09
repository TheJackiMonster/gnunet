#!/bin/bash
CONFIGURATION="test_namestore_api.conf"
trap "gnunet-arm -e -c $CONFIGURATION" SIGINT

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

rm -rf `$LOCATION -c $CONFIGURATION -s PATHS -o GNUNET_HOME`
TEST_RECORD_NAME_DNS="trust"
TEST_RECORD_VALUE_SMIMEA="49152 49153 53 0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971"
TEST_RECORD_VALUE_URI="49152 49152 256 10 10 \"http://lightest.nletlabs.nl/\""
which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

function start_peer
{
	gnunet-arm -s -c $CONFIGURATION
	gnunet-identity -C testego -c $CONFIGURATION
}

function stop_peer
{
	gnunet-identity -D testego -c $CONFIGURATION
	gnunet-arm -e -c $CONFIGURATION
}


start_peer
# Create a public SMIMEA record
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME_DNS -t BOX -V "$TEST_RECORD_VALUE_SMIMEA" -e never -c $CONFIGURATION
NAMESTORE_RES=$?

if [ $NAMESTORE_RES = 0 ]
then
  echo "PASS: Creating boxed name in namestore SMIMEA"
else
  echo "FAIL: Creating boxed name in namestore failed with $NAMESTORE_RES."
  stop_peer
  exit 1
fi

# Create a public URI record
gnunet-namestore -p -z testego -a -n $TEST_RECORD_NAME_DNS -t BOX -V "$TEST_RECORD_VALUE_URI" -e never -c $CONFIGURATION
NAMESTORE_RES=$?

if [ $NAMESTORE_RES = 0 ]
then
  echo "PASS: Creating boxed name in namestore URI"
else
  echo "FAIL: Creating boxed name in namestore failed with $NAMESTORE_RES."
  stop_peer
  exit 1
fi

stop_peer