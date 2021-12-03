# blind-csp

Vocdoni blind-csp is a modular API backend for Certification Service Providers (CSP) using Blind signatures (among others).

Currently supported signature types are: PLAIN ECDSA and ECDSA BLIND (on secp256k1)

Supports x509 certificates for client authentication.

Its design makes very easy to write new authentication handlers such as the ones found in the `handlers/` directory.

## Salted keys

For making the CSP voter approval valid only for a specific voting process (processId), a deterministic key derivation 
is used. So the CSP is only required to publish a single root public key. The specific per-election keys will be computed
independently by all parties (CSP will derive its election private key and the election organizers will derive the election
public key). 

To this end we use the following simple approach (G is the EC generator):

```
PubKeyRootCSP = PrivKeyRootCSP * G
PrivKey2 = PrivkeyRootCSP + ProcessId
PubKey2 = PubKeyRootCSP + ProcessId
```

So if PubKey2 becomes the election CSP public key, there is no way the CSP can share signatures before the processId is known
and there is no way to reuse a CSP signature for a different election process.

![flow diagram](https://raw.githubusercontent.com/vocdoni/blind-csp/master/misc/blind_csp_flow.svg)

## API

The HTTP(s) API is very minimalistic (as follows):

```
curl -X POST https://server.foo/v1/auth/processes/<processId>/<signatureType>/<action>
```
+ processId: is a 32 byte hexadecimal string which identifies the process. It is used to salt the CSP private and public keys
+ signatureType: is either `blind` or `ecdsa`
+ action: is either `auth` or `sign`

### 1. Authentication and token retreival

```js
curl -X POST https://server.foo/v1/auth/processes/12345.../blind/auth -d '{ "authData": ["data-required-by-the-handler"] }'

// HTTP 200
{
	"tokenR": "0x1234567890abcde..."
}

// HTTP 400
{
	"error": "Message goes here"
}
```

### 2. CSP Blind signature

The signature performed by the CSP key salted with processId, of the blinded payload 

```js
curl -X POST https://server.foo/v1/auth/processes/12345.../blind/sign -d '{ "payload": "0xabcdef...", "tokenR": "0x123bcde..." }'

// HTTP 200
{
	"signature": "0x1234567890abcde..." // the blind signature
}

// HTTP 400
{
	"error": "Message goes here"
}
```

## Usage

See the `test.sh` file for a full flow example.

```golang
$ go run . --loglevel=debug --handler=uniqueIp
Using path /home/user/.blindcsp
2021-11-29T23:59:53+01:00	INFO	blind-ca/main.go:124	logger construction succeeded at level debug with output stdout
2021-11-29T23:59:53+01:00	INFO	blind-ca/main.go:142	using ECDSA signer with address 0xAF1fd9cD2F2A24107757EC58561522869e32F7DF
2021-11-29T23:59:53+01:00	INFO	blind-ca/main.go:157	using handler dummy
2021-11-29T23:59:53+01:00	INFO	httprouter/httprouter.go:120	starting go-chi http server
2021-11-29T23:59:53+01:00	INFO	httprouter/httprouter.go:134	router ready at http://[::]:5000
2021-11-29T23:59:53+01:00	INFO	blind-ca/main.go:186	CSP root public key: fef679c673157994e882b85ceeb23ba86f0873493e96f11e2...
2021-11-29T23:59:53+01:00	DEBUG	csp/csp.go:68	initializing persistent storage on /home/user/.blindcsp/dummy
2021-11-29T23:59:53+01:00	INFO	httprouter/httprouter.go:148	added namespace bearerStd
2021-11-29T23:59:53+01:00	INFO	httprouter/httprouter.go:179	added public handler for namespace bearerStd with pattern /v1/auth/processes/{processId}/{signType}/auth
2021-11-29T23:59:53+01:00	INFO	bearerstdapi/bearerstdapi.go:140	registered POST public method for path /v1/auth/processes/{processId}/{signType}/auth
2021-11-29T23:59:53+01:00	INFO	httprouter/httprouter.go:179	added public handler for namespace bearerStd with pattern /v1/auth/processes/{processId}/{signType}/sign
2021-11-29T23:59:53+01:00	INFO	bearerstdapi/bearerstdapi.go:140	registered POST public method for path /v1/auth/processes/{processId}/{signType}/sign
```

```golang
$ go run . --help
      --baseURL string        base URL path for serving the API (default "/v1/auth")
      --dataDir string        datadir for storing files and config (default "/home/user/.blindcsp")
      --domain string         domain name for tls with letsencrypt (port 443 must be forwarded)
      --handler string        the authentication handler to use, available: {dummy uniqueIp idCat} (default "dummy")
      --handlerOpts strings   options that will be passed to the handler
      --key string            private CSP key as hexadecimal string (leave empty for autogenerate)
      --logLevel string       log level {debug,info,warn,error} (default "info")
      --port int              port to listen (default 5000)
```

## Links

1. H. Mala, N. Nezhadansari, *"New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem"* [https://sci-hub.st/10.1109/iccke.2013.6682844](https://sci-hub.st/10.1109/iccke.2013.6682844) Implementation: [https://github.com/arnaucube/go-blindsecp256k1](https://github.com/arnaucube/go-blindsecp256k1)
