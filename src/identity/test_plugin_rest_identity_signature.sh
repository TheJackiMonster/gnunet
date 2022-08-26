#!/usr/bin/bash

# https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3

header='{"alg":"EdDSA"}'
payload='Example of Ed25519 signing'
key='{  "kty":"OKP",
        "crv":"Ed25519",
        "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
        "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }'

header_payload_test="eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
signature_test="hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

base64url_add_padding() {
    for i in $( seq 1 $(( 4 - ${#1} % 4 )) ); do padding+="="; done
    echo "$1""$padding"
}

base64url_encode () {
    echo -n -e "$1" | base64 -w0 | tr '+/' '-_' | tr -d '='
}

base64url_decode () {
    padded_input=$(base64url_add_padding "$1")
    echo -n "$padded_input" | basenc --base64url -d
}

base32crockford_encode () {
    echo -n -e "$1" | basenc --base32hex | tr 'IJKLMNOPQRSTUV' 'JKMNPQRSTVWXYZ'
}

echo -n "jwk: "
echo $key | jq

# Create Header
# 65556 (decimal)
# = 00000000-00000001-00000000-00010100 (binary little endian)
# = 00-01-00-14 (hex little endian)
header_hex=("00" "01" "00" "14")

# Convert secret JWK to HEX array
key_hex=( $( base64url_decode $( echo -n "$key" | jq -r '.d' ) | xxd -p | tr -d '\n' | fold -w 2 | tr '\n' ' ' ) )

# Concat header and key
header_key_hex=(${header_hex[@]} ${key_hex[@]})

# Encode with Base32Crogford
key_gnunet=$(echo -n "${header_key_hex[*]}" | tr -d " " | xxd -p -r | basenc --base32hex | tr 'IJKLMNOPQRSTUV' 'JKMNPQRSTVWXYZ' | tr -d "=")
echo "gnunet skey: $key_gnunet"

# Create ego
gnunet-identity -C ego9696595726 -X -P "$key_gnunet"

# Test base64url encoding and header.payload generation
header_payload_enc="$(base64url_encode "$header").$(base64url_encode "$payload")"
if [ $header_payload_enc != $header_payload_test ] ; 
then 
    exit 1
fi
echo "header.payload: $header_payload_enc"

# Sign JWT
signature_enc=$(curl -s "localhost:7776/sign?user=ego9696595726&data=$header_payload_enc" | jq -r '.signature')
jwt="$header_payload_enc.$signature_enc"
echo "header.payload.signature: $jwt"

gnunet-identity -D ego9696595726

if [ $signature_enc !=  $signature_test ]
then
    echo "Signature does not check out:"
    echo "$signature_enc"
    echo "$signature_test"
    exit 1
else 
    echo "Signature does check out!"
    exit 1
fi

