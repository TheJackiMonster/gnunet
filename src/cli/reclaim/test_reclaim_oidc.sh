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

which timeout >/dev/null 2>&1 && DO_TIMEOUT="timeout 30"

RES=0
TEST_ATTR="test"
REDIRECT_URI="https://example.gns.alt/my_cb"
SCOPE="\"openid email name\""
gnunet-arm -s -c test_reclaim.conf
gnunet-arm -i rest -c test_reclaim.conf
gnunet-arm -I
gnunet-identity -C testego -c test_reclaim.conf
gnunet-identity -C rpego -c test_reclaim.conf
TEST_KEY=$(gnunet-identity -d -e rpego -q -c test_reclaim.conf)
SUBJECT_KEY=$(gnunet-identity -d -e testego -q -c test_reclaim.conf)
gnunet-reclaim -e testego -a email -V john@doe.gnu -c test_reclaim.conf
gnunet-reclaim -e testego -a name -V John -c test_reclaim.conf

# Register client
gnunet-namestore -z rpego -a -n @ -t RECLAIM_OIDC_CLIENT -V "My RP" -e 1d -p -c test_reclaim.conf
gnunet-namestore -z rpego -a -n @ -t RECLAIM_OIDC_REDIRECT -V $REDIRECT_URI -e 1d -p -c test_reclaim.conf

gnunet-gns -u @.$TEST_KEY -t RECLAIM_OIDC_REDIRECT -c test_reclaim.conf
curl -v -X POST -H -v "http://localhost:7776/openid/login" --data "{\"identity\": \"$SUBJECT_KEY\"}"

PKCE_CHALLENGE=$(echo -n secret | openssl dgst -binary -sha256 | openssl base64 | sed 's/\=//g' | sed 's/+/-/g' | sed 's/\//_/g')

CODE=$(curl -H "Cookie: Identity=$SUBJECT_KEY" "http://localhost:7776/openid/authorize?client_id=$TEST_KEY&response_type=code&redirect_uri=$REDIRECT_URI&scope=openid&claims=%7B%22userinfo%22%3A%20%7B%22email%22%3A%20%7B%22essential%22%20%20%20%20%3A%20true%7D%7D%2C%22id_token%22%3A%20%7B%22email%22%3A%20%7B%22essential%22%3A%20true%7D%7D%7D&state=xyz&code_challenge=$PKCE_CHALLENGE&code_challenge_method=S256" \
  -sS -D - -o /dev/null | grep "Location: " | cut -d" " -f2 | cut -d"?" -f2 | cut -d"&" -f1 | cut -d"=" -f2)

echo "Code: $CODE"

curl -v -X POST -u$TEST_KEY:"secret" "http://localhost:7776/openid/token?client_id=$TEST_KEY&response_type=code&redirect_uri=$REDIRECT_URI&scope=openid&claims=%7B%22userinfo%22%3A%20%7B%22email%22%3A%20%7B%22essential%22%20%20%20%20%3A%20true%7D%7D%2C%22id_token%22%3A%20%7B%22email%22%3A%20%7B%22essential%22%3A%20true%7D%7D%7D&state=xyz&grant_type=authorization_code&code=$CODE&code_verifier=secret"

gnunet-identity -D testego -c test_reclaim.conf
gnunet-identity -D rpego -c test_reclaim.conf
gnunet-arm -e -c test_reclaim.conf
if test $RES != 0
then
  echo "Failed."
fi

