# blind-csp

Vocdoni blind-csp is a modular API backend for [Certification Service Providers (CSP)](https://en.wikipedia.org/wiki/Certificate_authority) using [Blind signatures](https://en.wikipedia.org/wiki/Blind_signature) (among others).

Blind signatures were first suggested by David Chaum: a cryptographic scheme that allows for signatures over disguised (blinded) messages. The blinder (voter in our scenario) can then un-blind the signature and use it as a normal/standard one. This protocol was designed for RSA, but we use it over the [EC secp256k1](https://github.com/arnaucube/go-blindsecp256k1).

The API server supports [x509 certificates](https://en.wikipedia.org/wiki/X.509) for client authentication so it is a convinient way for authenticating standard/official certificates while preserving the privacy.
Its design makes very easy to write new authentication handlers such as the ones found in the `handlers/` directory. A pretty useful use case is to authenticate via SMS (already supported) but there are other pretty cool handlers that can be implemented such as authentication via Discord, Twitter or E-residency cards.

## Salted keys

The CSP server cannot see the payload of what is being signed (it is blinded) and since the server cannot see what is signing a valid signature proof provided by the CSP might be reused or requested for a different validation process. This is not something is desired to happen because the voter can then vote on processes where is not allowed to.

For making the CSP voter approval valid only for a specific process (identified by a 20 bytes word: electionId), a deterministic key derivation 
is used. So the CSP is only required to publish a single root public key. The specific per-process keys will be computed
independently by all parties (CSP will derive its election private key and the process organizers will derive the election public key). 

To this end we use the following simple approach (G is the EC generator):

```
PubKeyRootCSP = PrivKeyRootCSP * G
PrivKey2 = PrivkeyRootCSP + electionId
PubKey2 = PubKeyRootCSP + electionId
```

So if PubKey2 becomes the election CSP public key, there is no way the CSP can share signatures before the electionId is known
and there is no way to reuse a CSP signature for a different election process.

![flow diagram](https://raw.githubusercontent.com/vocdoni/blind-csp/master/misc/blind_csp_flow.svg)

## API

The HTTP(s) API is very minimalistic and the handler implements the method for authentication which is one of the core parts of the CSP.
Let's see some examples using the Simple Math handler that requires the user to solve a 
simple math challenge.

The handler requires a two steps authentication process:
1. Requires a name and replies with the challenge (["123","200"])
2. Requires the challenge solution (["323"])

### 1. Handler information

The `info` endpoint provides the description of the authentication handler. 
The `authType` parameter indicates the kind of authentication is required by the CSP.
Curently only `auth` as authType is supported, but `oauth` or others might be added in the future.

The `signatureType` is a string array containing the list of supported signature types (used as the CSP proof).
Currently the supported signature types are `blind` for ECDSA blind signature, `ecdsa` for plain ECDSA signature over an arbitrary payload, 
and `sharedkey` for fetching a shared secret (signature of electionId).

The `authSteps` object array describes the authentication steps and its parameters for a given authentication handler.
So in the following example there are two steps (size of the object array), the first one requires a
text field named `name`. The second a 4 digits integer named `solution`.

```js
curl http://127.0.0.1:5000/v1/auth/elections/info

{
  "title": "Simple math challenge",
  "authType": "auth",
  "signatureType": ["blind","ecdsa","sharedkey"],
  "authSteps": [
    {
      "title": "name",
      "type": "text"
    },
    {
      "title": "solution",
      "type": "int4"
    }
  ]
}
```

### Authentication steps

The endpoint `blind/auth/<step>`, where step is a 32 byte integer, handles the authentication steps for the handler. 
The client needs to perform all steps (in our case 2) starting from 0, successfully and serially.

#### Step 0

An `authToken` is provided by the CSP in order to identify the client
in the following steps.

An array of strings named `response` might be returned by the handler if the client
requires some data for performing the next step. In our case the challenge numbers that
must be sum by the client.

- Request
```bash
curl -s 127.0.0.1:5000/v1/auth/elections/A9893a41fc7046d66d39fdc073ed901af6bec66ecc070a97f9cb2dda02b11265/blind/auth/0 -X POST -d '{"authData":["John Smith"]}'
```
- Response OK
```json
{
      "authToken": "9ba29669-3a38-43ac-a8f6-d6ac99d2e3a2",
      "response": [
        "141",
        "484"
      ]
}
```
- Response Error
```json
{
	"error": "Error invalid name"
}
```

#### Step 1

In the final step, if the authentication challenge is resolved, the CSP returns `token`, the data
that can be used by the client to prepare and ask for the signature. In our case the signature is
of type `blind` so the token is the curve point `R` required for blinding the payload.

- Request 
```bash
# for the authData the string 574 is passed as it is the sum of 141 and 484 as integers
curl -s 127.0.0.1:5000/v1/auth/elections/A9893a41fc7046d66d39fdc073ed901af6bec66ecc070a97f9cb2dda02b11265/ecdsa/auth/1 -X POST -d '{"authToken":"8b16df36-9720-487f-b3eb-a46dfdebdb36", "authData":["574"]}'
```
- Response OK
```json
{
      "token": "0d2347cf59313bdb4038f0c6643e9289d694c1c67d4d1d66f56968e374d48669"
}
```
- Response Error
```json
{
	"error": "Message goes here"
}
```

### 2. CSP Blind signature

Is the signature performed by the CSP. The payload to sign is usually an ephemeral ECDSA public key that the client creates for performing the vote for a specific voting process, but can also be any kind of privacy preserving digital ID.

- Request
```bash
curl -X POST https://server.foo/v1/auth/processes/12345.../blind/sign -d '{ "payload": "0xabcdef...", "token": "0x123bcde..." }'
```
- Response OK
```json
{
	"signature": "0x1234567890abcde..." // the blind signature
}
```
- Response Error
```json
{
	"error": "Invalid token"
}
```

### 3. Shared Key

The shared key is a common key for all users belonging to the same electionId.
It might be used as shared key for encrypting process data so only the users that are able to 
authenticate can decrypt the data.

The shared key is the ECDSA salted signature of a keccak256 hash of a given electionId.

The sharedkey endpoint requires the same authentication steps described by the `info` method.
However the handler might apply different restrictions such as allow the authentication succeed more
than one time.

- Request
```bash
curl -s 127.0.0.1:5000/v1/auth/elections/A9893a41fc7046d66d39fdc073ed901af6bec66ecc070a97f9cb2dda02b11265/sharedkey/0 -X POST -d '{"authData":["John Smith"]}'
```
- Response OK
```json
{     
      "authToken":"12ab5ec4-bfc5-4dd1-896f-46ae06b15e81",
      "response":["232","333"]
}
```
- Response Error
```json
{
	"error": "Message goes here"
}
```
- Request
```bash
curl -s 127.0.0.1:5000/v1/auth/elections/A9893a41fc7046d66d39fdc073ed901af6bec66ecc070a97f9cb2dda02b11265/sharedkey/1 -X POST -d '{"authToken":"12ab5ec4-bfc5-4dd1-896f-46ae06b15e81", "authData":["565"]}'
```
- Response OK
```json
{
      "sharedkey": "a6d7b59f5f6dfff418464c3fa2895ad872d402bda6e85f1ba62fe6f50f703ea87247ca8bf34a00a15cd768ba44cd6c99044a2ff4b6f837f77c243102872f03c101"
}
```
- Response Error
```json
{
  "error": "invalid authData"
}
```

### 4. Indexer

Some handlers might enable an indexer in order to let the user know the list of elections where he is eligible for participating.
The indexer endpoint takes as URL parameter a unique identifier by the user (hexadecimal string format) and returns the list of
election identifiers (if any).

- Request
```bash
curl http://127.0.0.1:5000/v1/auth/elections/indexer/a216bc43310f46d66d39fdc073ed901af6bec66ecc070a97f9cb2dda01ba0241
```
- Response Ok
``` json
{
  "elections": [
    {
      "electionId": "2222222222222222222222222222222222222222222222222222222222222222",
      "remainingAttempts": 5,
      "consumed": false,
      "extra": [
        "41"
      ]
    },
    {
      "electionId": "1111111111111111111111111111111111111111111111111111111111111111",
      "remainingAttempts": 5,
      "consumed": false,
      "extra": [
        "41"
      ]
    }
  ]
}

```
- Response Error
```json
{
  "error": "user not found"
}
```

## Usage

See the `test.sh` file for a full flow example.

```golang
$ go run . --loglevel=debug --handler=simpleMath
Using path /home/user/.blindcsp
2022-06-17T16:29:19+02:00	INFO	blind-csp/main.go:124	logger construction succeeded at level debug with output stdout
2022-06-17T16:29:19+02:00	INFO	blind-csp/main.go:142	using ECDSA signer with address 0x5D7Ad549556B40E05ef7576B26b368c824263B30
2022-06-17T16:29:19+02:00	INFO	blind-csp/main.go:157	using handler simpleMath
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:150	starting go-chi http server
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:164	router ready at http://[::]:5000
2022-06-17T16:29:19+02:00	INFO	blind-csp/main.go:186	CSP root public key: 02c5d98b525d844440f16d4e0492dc8e4c8188ab00ed3d4bb104365280db8a9252
2022-06-17T16:29:19+02:00	DEBUG	csp/csp.go:52	initializing persistent storage on /home/p4u/.blindcsp/simpleMath
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:178	added namespace bearerStd
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/ping
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered GET public method for path /v1/auth/elections/ping
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/info
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered GET public method for path /v1/auth/elections/info
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/{electionId}/{signType}/auth/{step}
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered POST public method for path /v1/auth/elections/{electionId}/{signType}/auth/{step}
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/{electionId}/{signType}/auth
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered POST public method for path /v1/auth/elections/{electionId}/{signType}/auth
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/{electionId}/{signType}/sign
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered POST public method for path /v1/auth/elections/{electionId}/{signType}/sign
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/{electionId}/sharedkey/{step}
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered POST public method for path /v1/auth/elections/{electionId}/sharedkey/{step}
2022-06-17T16:29:19+02:00	INFO	httprouter/httprouter.go:220	added public handler for namespace bearerStd with pattern /v1/auth/elections/{electionId}/sharedkey
2022-06-17T16:29:19+02:00	INFO	bearerstdapi/bearerstdapi.go:160	registered POST public method for path /v1/auth/elections/{electionId}/sharedkey
```

```golang
$ go run . --help
      --baseURL string        base URL path for serving the API (default "/v1/auth")
      --dataDir string        datadir for storing files and config (default "/home/user/.blindcsp")
      --domain string         domain name for tls with letsencrypt (port 443 must be forwarded)
      --handler string        the authentication handler to use, available: {dummy uniqueIp idCat rsa} (default "dummy")
      --handlerOpts strings   options that will be passed to the handler
      --key string            private CSP key as hexadecimal string (leave empty for autogenerate)
      --logLevel string       log level {debug,info,warn,error} (default "info")
      --port int              port to listen (default 5000)
```

## Links

1. H. Mala, N. Nezhadansari, *"New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem"* [https://sci-hub.st/10.1109/iccke.2013.6682844](https://sci-hub.st/10.1109/iccke.2013.6682844) Implementation: [https://github.com/arnaucube/go-blindsecp256k1](https://github.com/arnaucube/go-blindsecp256k1)
