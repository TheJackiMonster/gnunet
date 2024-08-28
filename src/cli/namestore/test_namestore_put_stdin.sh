#!/bin/bash
CONFIGURATION="test_namestore_api.conf"
trap "gnunet-arm -e -c $CONFIGURATION" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --section arm 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `$LOCATION -c $CONFIGURATION -s PATHS -o GNUNET_HOME`
TEST_RECORD_NAME="www3"
TEST_RECORD_NAME2="www"
TEST_IP="8.7.6.5"
TEST_IP2="1.2.3.4"

which timeout &> /dev/null && DO_TIMEOUT="timeout 5"

function start_peer
{
	gnunet-arm -s -c $CONFIGURATION
	gnunet-identity -C testego -c $CONFIGURATION
  gnunet-identity -C testego2 -c $CONFIGURATION
}

function stop_peer
{
	gnunet-identity -D testego -c $CONFIGURATION
  gnunet-identity -D testego2 -c $CONFIGURATION
	gnunet-arm -e -c $CONFIGURATION
}


start_peer
# Create a public record
EGOKEY=`gnunet-identity -d | grep testego2 | cut -d' ' -f3`
gnunet-namestore -B 3 -a -c $CONFIGURATION -S <<EOF
${TEST_RECORD_NAME}.testego:
  A 3600000000 [pr] $TEST_IP
  TXT 21438201833 [r] $TEST_IP2

  TXT 21438201833 [r] aslkdj asdlkjaslkd 231!

${TEST_RECORD_NAME}1.testego:
  A 3600000000 [pr] $TEST_IP
  TXT 21438201833 [r] $TEST_IP2

  TXT 21438201833 [r] aslkdj asdlkjaslkd 232!

${TEST_RECORD_NAME}2.testego:
  A 3600000000 [pr] $TEST_IP
  TXT 21438201833 [r] $TEST_IP2

  TXT 21438201833 [r] aslkdj asdlkjaslkd 233!

${TEST_RECORD_NAME}3.testego:
  A 3600000000 [pr] $TEST_IP
  TXT 21438201833 [r] $TEST_IP2

  TXT 21438201833 [r] aslkdj asdlkjaslkd 234!

${TEST_RECORD_NAME}4.testego:
  AAAA 324241223 [prS] ::dead:beef
  A 111324241223000000 [pC] 1.1.1.1

www7.$EGOKEY:
  A 3600000000 [pr] $TEST_IP

EOF
NAMESTORE_RES=$?
gnunet-identity -d -c $CONFIGURATION
gnunet-namestore -D -r -c $CONFIGURATION
stop_peer

if [ $NAMESTORE_RES = 0 ]
then
  echo "PASS: Recordline import in namestore"
else
  echo "FAIL: Recordline import in namestore failed with $NAMESTORE_RES."
  exit 1
fi
