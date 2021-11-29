#!/bin/bash
HOST=${HOST:-"127.0.0.1:5000/v1/auth/processes/1234"}

echo "=> ECDSA blind signatre"
R="$(curl -s $HOST/blind/auth -X POST -d '{"authData":[]}' | jq -Mc .tokenR)"
[ "$R" == "" ] && { echo "Error receiving signerR"; exit 1; }
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s $HOST/blind/sign -X POST -d  '{"tokenR":'$R', "payload":"'$hash'"}'

echo "=> ECDSA signatre"
R="$(curl -s $HOST/ecdsa/auth -X POST -d '{"authData":[]}' | jq -Mc .tokenR)"
[ "$R" == "" ] && { echo "Error receiving signerR"; exit 1; }
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s $HOST/ecdsa/sign -X POST -d  '{"tokenR":'$R', "payload":"'$hash'"}'
