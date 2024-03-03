#!/bin/bash
# This file is in the public domain.

if ! which certutil > /dev/null
then
    echo "certutil required"
    exit 77
fi

if ! which openssl > /dev/null
then
    echo "certutil required"
    exit 77
fi

TEST_DOMAIN="www.test"
GNUNET_TMP="$(gnunet-config -f -s PATHS -o GNUNET_TMP)"
PROXY_CACERT="$(gnunet-config -f -c test_gns_proxy.conf -s gns-proxy -o PROXY_CACERT)"

# Delete old files before starting test
rm -rf "$GNUNET_TMP/test-gnunet-gns-testing/"
gnunet-arm -s -c test_gns_proxy.conf
gnunet-gns-proxy-setup-ca -c test_gns_proxy.conf

openssl genrsa -des3 -passout pass:xxxx -out server.pass.key 2048
openssl rsa -passin pass:xxxx -in server.pass.key -out local.key
rm server.pass.key
openssl req -new -key local.key -out server.csr \
  -subj "/C=DE/O=GNUnet/OU=GNS/CN=test.local"
openssl x509 -req -days 1 -in server.csr -signkey local.key -out local.crt
openssl x509 -in local.crt -out local.der -outform DER
HEXCERT=`xxd -p local.der | tr -d '\n'`
#echo "This is the certificate the server does not use: $HEXCERT"
OLDBOXVALUE="6 8443 52 3 0 0 $HEXCERT"


openssl req -new -key local.key -out server.csr \
  -subj "/C=DE/O=GNUnet/OU=GNS/CN=test.local"
openssl x509 -req -days 1 -in server.csr -signkey local.key -out local.crt
openssl x509 -in local.crt -out local.der -outform DER
HEXCERT=`xxd -p local.der | tr -d '\n'`
#echo "This is the certificate the server does use: $HEXCERT"
BOXVALUE="6 8443 52 3 0 0 $HEXCERT"

SERVER_CACERT="$GNUNET_TMP/server_cacert.pem"
cat local.crt > "$SERVER_CACERT"
cat local.key >> "$SERVER_CACERT"

gnunet-identity -C test -c test_gns_proxy.conf
gnunet-namestore -p -z "test" -a -n www -t A -V 127.0.0.1 -e never -c test_gns_proxy.conf
gnunet-namestore -p -z "test" -a -n www -t LEHO -V "test.local" -e never -c test_gns_proxy.conf
gnunet-namestore -p -z "test" -a -n www -t BOX -V "$OLDBOXVALUE" -e never -c test_gns_proxy.conf
gnunet-namestore -p -z "test" -a -n www -t BOX -V "$BOXVALUE" -e never -c test_gns_proxy.conf

gnunet-arm -i gns-proxy -c test_gns_proxy.conf

#gnurl --socks5-hostname 127.0.0.1:7777 "https://$TEST_DOMAIN" -v --cacert "$PROXY_CACERT"
./test_gns_proxy -A "$PROXY_CACERT" -S "$SERVER_CACERT" -p 8443 -c test_gns_proxy.conf

RES=$?

rm "$PROXY_CACERT"
rm "$SERVER_CACERT"

gnunet-arm -e test_gns_proxy.conf

if test $RES != 0
then
  echo "Failed"
  exit 1
fi
