#!/bin/sh
# This file is in the public domain.
trap "gnunet-arm -e -c test_namestore_api.conf" INT

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

rm -rf `gnunet-config -c test_namestore_api.conf -f -s paths -o GNUNET_TEST_HOME`
which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 5"

MY_EGO="myego"
gnunet-arm -s -c test_namestore_api.conf
gnunet-identity -C $MY_EGO -c test_namestore_api.conf
gnunet-namestore-zonefile -c test_namestore_api.conf < example_zonefile
res=$?
gnunet-identity -D $MY_EGO -c test_namestore_api.conf
gnunet-arm -e -c test_namestore_api.conf

if [ $res != 0 ]; then
  echo "FAIL: Zone import failed."
  exit 1
fi


