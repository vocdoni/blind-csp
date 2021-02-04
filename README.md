# blind-ca

Vocdoni blind-ca is a modular RPC backend for client authentication and signature retreival.

Currently it supports ECDSA and ECDSA_BLIND signature types.

Its design makes very easy to write new authentication handlers such as the ones found in the `handlers/` directory.

The API is very simple (there exist only two methods: auth and sign) and follows the same standard of all Vocdoni components.

### Authentication and token retreival

Query
```json
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
```json
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
```json
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
```json
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

