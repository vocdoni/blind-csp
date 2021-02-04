# blind-ca

Vocdoni blind-ca is a modular RPC backend for client authentication and signature retreival.

Currently it supports ECDSA and ECDSA_BLIND signature types.

Its design makes very easy to write new authentication handlers such as the ones found in the `handlers/` directory.

The API is very simple (there exist only two methods: auth and sign) and follows the same standard of all Vocdoni components.

### Authentication and token retreival

Query
```
{
  "id": "req-12345678",
  "request": {
    "method": "auth",
    "signatureType": "ECDSA" | "ECDSA_BLIND", // one of the currently supported types
    "authData": ["John Smith","18-10-2001"], // optional authentication specific data if the CA requires it
  }
}
```
Reply
```
{
  "id": "req-12345678",          // id of the originating request
  "response": {
    "request": "req-12345678",   // request id here as well
    "ok": true,                  // whetever there has been an error or not
    "error": "a possible error", // if error, the message
    "reply": "welcome John",     // optional reply, depends on the specific CA implementation
    "token": "0x123456789",      // hexadecimal string with the token (and R point if blind signature request)
  }
}
```

### CA signature

Query
```
{
  "id": "req-12345678",
  "request": {
    "method": "sign",
    "signatureType": "ECDSA" | "ECDSA_BLIND", // must be the same type of the authentication step
    "token": "0x123456789",       // hexadecimal string with the token (and R point if blind signature request)
    "messageHash": "0x1234",      // if blind signature, the message hash to sign
    "message": "base64",          // if ecdsa signature, the message to sign (will be hashed)
  }
}
```
Reply
```
{
  "id": "req-12345678",          // id of the originating request
  "response": {
    "request": "req-12345678",   // request id here as well
    "ok": true,                  // whetever there has been an error or not
    "error": "a possible error", // if error, the message
    "caSignature": "0x1234567",  // hexadecimal string containing the CA signature proof
  }
}
```

## Usage

```bash
$ go run . --loglevel=debug --handler=uniqueIp

2021-02-04T14:08:34+01:00       INFO    vocdoni-blind-ca/main.go:45     logger construction succeeded at level debug and output stdout
2021-02-04T14:08:34+01:00       INFO    vocdoni-blind-ca/main.go:52     new private key generated: 1ca5cdddfef01ab0a5bc1b7b71b13bdbcef963c372a873feacbac01526608413
2021-02-04T14:08:34+01:00       INFO    vocdoni-blind-ca/main.go:53     CA public key: 023ce675fd2317e2015f4f10667556ca2f521e0eeef21325290d9ba3996501aa7b
2021-02-04T14:08:34+01:00       INFO    vocdoni-blind-ca/main.go:59     using ECDSA signer with address 0xBC0525b0cC3eb177a0418760A990f17a25ED8aF5
2021-02-04T14:08:34+01:00       INFO    endpoint/httpws.go:107  creating API service
2021-02-04T14:08:34+01:00       INFO    endpoint/httpws.go:162  creating proxy service, listening on 0.0.0.0:5000
2021-02-04T14:08:34+01:00       INFO    mhttp/proxy.go:133      starting go-chi http server
2021-02-04T14:08:34+01:00       INFO    mhttp/proxy.go:148      proxy ready at http://[::]:5000
2021-02-04T14:08:34+01:00       INFO    vocdoni-blind-ca/main.go:132    adding request method under /ca namespace
2021-02-04T14:08:34+01:00       DEBUG   router/router.go:66     adding new handler auth for namespace /ca
2021-02-04T14:08:34+01:00       INFO    vocdoni-blind-ca/main.go:137    adding sign method under /ca namespace
2021-02-04T14:08:34+01:00       DEBUG   router/router.go:66     adding new handler sign for namespace /ca
```

```bash
$ go run . --help

      --certs stringArray   list of PEM certificates to import to the HTTP(s) server
      --dataDir string      datadir for storing files and config (default "/home/p4u/.vocdoni-ca")
      --domain string       domain name for tls with letsencrypt (port 443 must be forwarded)
      --handler string      the authentication handler to use for the CA, available: {uniqueIp idCat dummy} (default "dummy")
      --key string          private CA key as hexadecimal string (leave empty for autogenerate)
      --loglevel string     log level {debug,info,warn,error} (default "info")
      --port int            port to listen (default 5000)
```

