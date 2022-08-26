#!/usr/bin/bash

# https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3

header='{"alg":"ES256"}'
payload='{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'

key='{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }'

header_payload_test=(
    101 121 74 104 98 71 99 105 79 105 74 70 85 122 73
    49 78 105 74 57 46 101 121 74 112 99 51 77 105 79 105
    74 113 98 50 85 105 76 65 48 75 73 67 74 108 101 72
    65 105 79 106 69 122 77 68 65 52 77 84 107 122 79 68
    65 115 68 81 111 103 73 109 104 48 100 72 65 54 76
    121 57 108 101 71 70 116 99 71 120 108 76 109 78 118
    98 83 57 112 99 49 57 121 98 50 57 48 73 106 112 48
    99 110 86 108 102 81)

base64url_add_padding() {
    for i in $( seq 1 $(( 4 - ${#1} % 4 )) ); do padding+="="; done
    echo "$1""$padding"
}

base64url_encode () {
    echo -n -e "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='
}

base64url_decode () {
    padded_input=$(base64url_add_padding "$1")
    echo -n "$padded_input" | tr '_-' '/+' | base64 -w0 --decode 
}

base32crockford_encode () {
    echo -n "$i" | basenc --base32hex | tr 'IJKLMNOPQRSTUV' 'JKMNPQRSTVWXYZ'
}

header_enc=$(base64url_encode "$header")
payload_enc=$(base64url_encode "$payload")

# encode header_payload test vektor
for i in "${header_payload_test[@]}"
do 
    header_payload_test_enc+=$(printf "\x$(printf %x $i)")
done

# test base64url encoding and header-payload concatenation
if [ "$header_enc.$payload_enc" != $header_payload_test_enc ] ; 
then 
    exit 1
fi

signature_enc=$(curl -s "localhost:7776/sign?user=tristan&data=$header_payload_enc" | jq -r '.signature')
jwt="$header_enc.$payload_enc.$signature_enc"
echo $jwt

# Convert secret JWK to GNUnet skey
key_dec=$(base64url_decode $( echo -n "$key" | jq -r '.d'))
for i in $(echo -n $key_dec | xxd -p | tr -d '\n' | fold -w 2)
do 
    echo -n "$i "
done
echo ""

# TODO: Test Signature
    # Gen key: Public Key GNS zone type value + d in crockford encoding
    # Create new ego with key
    # Check if signaure is valid using openssh
    # Check if signaure is valid with test vektor
