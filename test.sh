#!/bin/bash
R="$(curl -s 127.0.0.1:5000/ca -X POST -d '{"request":{"method":"auth", "request":"1234"}, "id":"1234"}' | jq -Mc .request.signerR)"
[ "$R" == "" ] && { echo "Error receiving signerR"; exit 1; }
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s 127.0.0.1:5000/ca -X POST -d  '{"request":{"method":"sign", "request":"1234", "signerR":'$R', "messageHash":"'$hash'"},"id":"1234"}' | jq .
