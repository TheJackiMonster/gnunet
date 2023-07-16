#!/bin/bash
trap "gnunet-arm -e -c test_identity.conf" SIGINT

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

rm -rf `gnunet-config -c test_identity.conf -s PATHS -o GNUNET_HOME -f`

which timeout >/dev/null 2>&1 && DO_TIMEOUT="timeout 30"

TEST_MSG="This is a test message. 123"
gnunet-arm -s -c test_identity.conf
gnunet-identity -C recipientego -c test_identity.conf
gnunet-identity -C recipientegoed -X -c test_identity.conf
RECIPIENT_KEY=`gnunet-identity -d -e recipientego -q -c test_identity.conf`
MSG_ENC=`gnunet-identity -W "$TEST_MSG" -k $RECIPIENT_KEY -c test_identity.conf`
if [ $? == 0 ]
then
  MSG_DEC=`gnunet-identity -R "$MSG_ENC" -e recipientego -c test_identity.conf`
fi
RECIPIENT_KEY_ED=`gnunet-identity -d -e recipientegoed -q -c test_identity.conf`
MSG_ENC_ED=`gnunet-identity -W "$TEST_MSG" -k $RECIPIENT_KEY_ED -c test_identity.conf`
if [ $? == 0 ]
then
  MSG_DEC_ED=`gnunet-identity -R "$MSG_ENC_ED" -e recipientegoed -c test_identity.conf`
fi
gnunet-identity -D recipientego -c test_identity.conf
gnunet-identity -D recipientegoed -c test_identity.conf
gnunet-arm -e -c test_identity.conf
if [ "$TEST_MSG" != "$MSG_DEC" ]
then
  diff  <(echo "$TEST_MSG" ) <(echo "$MSG_DEC")
  echo "Failed - \"$TEST_MSG\" != \"$MSG_DEC\""
  exit 1
fi
if [ "$TEST_MSG" != "$MSG_DEC_ED" ]
then
  diff  <(echo "$TEST_MSG" ) <(echo "$MSG_DEC_ED")
  echo "Failed - \"$TEST_MSG\" != \"$MSG_DEC_ED\""
  exit 1
fi
