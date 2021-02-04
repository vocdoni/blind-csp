#!/bin/bash
[ "$1" == "blind" ] && {
echo "=> ECDSA blind signatre"
R="$(curl -s 127.0.0.1:5000/ca -X POST -d '{"request":{"method":"auth", "signatureType":"ECDSA_BLIND", "request":"1234"}, "id":"1234"}' | jq -Mc .response.token)"
[ "$R" == "" ] && { echo "Error receiving signerR"; exit 1; }
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s 127.0.0.1:5000/ca -X POST -d  '{"request":{"method":"sign", "request":"1234", "signatureType":"ECDSA_BLIND", "token":'$R', "messageHash":"'$hash'"},"id":"1234"}' | jq .
exit 0
}

echo "=> ECDSA signatre"
R="$(curl -s 127.0.0.1:5000/ca -X POST -d '{"request":{"method":"auth", "signatureType":"ECDSA", "request":"1234"}, "id":"1234"}' | jq -Mc .response.token)"
[ "$R" == "" ] && { echo "Error receiving signerR"; exit 1; }
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s 127.0.0.1:5000/ca -X POST -d  '{"request":{"method":"sign", "request":"1234", "signatureType":"ECDSA", "token":'$R', "message":"'$hash'"},"id":"1234"}' | jq .
