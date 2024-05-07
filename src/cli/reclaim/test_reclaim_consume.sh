#!/bin/bash
trap "gnunet-arm -e -c test_reclaim.conf" SIGINT

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1>/dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_reclaim.conf -s PATHS -o GNUNET_HOME -f`

#  (1) PKEY1.user -> PKEY2.resu.user
#  (2) PKEY2.resu -> PKEY3
#  (3) PKEY3.user -> PKEY4


which timeout >/dev/null 2>&1 && DO_TIMEOUT="timeout 30"

TEST_ATTR="test"
gnunet-arm -s -c test_reclaim.conf
#gnunet-arm -i rest -c test_reclaim.conf
gnunet-arm -I
gnunet-identity -C testego -c test_reclaim.conf
gnunet-identity -C rpego -c test_reclaim.conf
SUBJECT_KEY=$(gnunet-identity -d -e rpego -q -c test_reclaim.conf)
TEST_KEY=$(gnunet-identity -d -e testego -q -c test_reclaim.conf)
gnunet-reclaim -e testego -a email -V john@doe.gnu -c test_reclaim.conf
gnunet-reclaim -e testego -a name -V John -c test_reclaim.conf
TICKET=$(gnunet-reclaim -e testego -U "urn:gns:$TEST_KEY" -i "email,name" -r $SUBJECT_KEY -c test_reclaim.conf | awk '{print $1}')
echo "Ticket: $TICKET"
gnunet-gns -u $TICKET -c test_reclaim.conf
gnunet-namestore -z testego -D -c test_reclaim.conf
gnunet-identity -d -c test_reclaim.conf
sleep 1
gnunet-reclaim -e rpego -U "urn:gns:$TEST_KEY" -C $TICKET -c test_reclaim.conf

RES=$?
gnunet-identity -D testego -c test_reclaim.conf
gnunet-identity -D rpego -c test_reclaim.conf
gnunet-arm -e -c test_reclaim.conf
if test $RES != 0
then
  echo "Failed."
fi

