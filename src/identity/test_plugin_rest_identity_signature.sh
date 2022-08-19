#!/usr/bin/bash

# https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3

header='{"alg":"ES256"}'
payload='{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'

header_payload_test=(
    101 121 74 104 98 71 99 105 79 105 74 70 85 122 73
    49 78 105 74 57 46 101 121 74 112 99 51 77 105 79 105
    74 113 98 50 85 105 76 65 48 75 73 67 74 108 101 72
    65 105 79 106 69 122 77 68 65 52 77 84 107 122 79 68
    65 115 68 81 111 103 73 109 104 48 100 72 65 54 76
    121 57 108 101 71 70 116 99 71 120 108 76 109 78 118
    98 83 57 112 99 49 57 121 98 50 57 48 73 106 112 48
    99 110 86 108 102 81)

base64url_encode () {
    echo -n -e "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='
}

# encode header_payload test vektor
for i in "${header_payload_test[@]}"
do 
    header_payload_test_enc+=$(printf "\x$(printf %x $i)")
done

header_enc=$(base64url_encode "$header")
payload_enc=$(base64url_encode "$payload")

# test base64url encoding and header & payload concatenation
if [ "$header_enc.$payload_enc" != $header_payload_test_enc ] ; 
then 
    exit 1
fi

signature_enc=$(curl -s "localhost:7776/sign?user=tristan&data=$header_payload_enc" | jq -r '.signature')
echo "$header_enc.$payload_enc.$signature_enc"

# TODO: Test Signature
    # Gen key: Public Key GNS zone type value + d in crockford encoding
    # Create new ego with key
    # Check if signaure is valid using openssh
    # Check if signaure is valid with test vektor
