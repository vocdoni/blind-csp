#!/bin/bash
HOST=${HOST:-"127.0.0.1:5000/v1/auth/elections/A9893a41fc7046d66d39fdc073ed901af6bec66ecc070a97f9cb2dda02b11265"}
#set -x

get_R_simplemath() {
	[ -z "$1" ] && {
		echo "auth and signature type missing"
		exit 1
	}
	local auth0="$(curl -s $HOST/$1/0 -X POST -d '{"authData":["John Smith"]}')"
	local authToken="$(echo $auth0 | jq -Mc .authToken)"
	local challenge1="$(echo $auth0 | jq -Mc '.response | .[0]' | tr -d \")"
	local challenge2="$(echo $auth0 | jq -Mc '.response | .[1]' | tr -d \")"
	[ -z "$challenge1" -o -z "$challenge2" ] && exit
	local solution=$(($challenge1 + $challenge2))
	[ "$1" == "sharedkey" ] && {
		echo "$(curl -s $HOST/$1/1 -X POST -d '{"authToken":'$authToken', "authData":["'$solution'"]}' | jq -Mc .sharedkey)"
	} || {
		echo "$(curl -s $HOST/$1/1 -X POST -d '{"authToken":'$authToken', "authData":["'$solution'"]}' | jq -Mc .token)"
	}
}

echo "=> ECDSA blind signatre"
R=$(get_R_simplemath blind/auth)
echo "R is $R"
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s $HOST/blind/sign -X POST -d  '{"token":'$R', "payload":"'$hash'"}'


echo "=> ECDSA signatre"
R=$(get_R_simplemath ecdsa/auth)
echo "R is $R"
hash="$(echo $RANDOM | sha256sum | awk '{print $1}')"
curl -s $HOST/ecdsa/sign -X POST -d  '{"token":'$R', "payload":"'$hash'"}'

echo "=> Shared key"
SK=$(get_R_simplemath sharedkey)
[ "$SK" == "" ] && { echo "Error receiving shared key"; exit 1; }
echo "sharedkey: $SK"
