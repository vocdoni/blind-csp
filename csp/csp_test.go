package csp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"testing"

	"github.com/arnaucube/go-blindsecp256k1"
	qt "github.com/frankban/quicktest"
	"go.vocdoni.io/dvote/crypto/ethereum"
)

func TestBlindCA(t *testing.T) {
	// Generate a new signing key
	signer := ethereum.SignKeys{}
	err := signer.Generate()
	qt.Assert(t, err, qt.IsNil)
	_, priv := signer.HexString()
	pubdesc, err := ethereum.DecompressPubKey(signer.PublicKey())
	qt.Assert(t, err, qt.IsNil)
	t.Logf("using root pubkey:%x privkey:%s", pubdesc, priv)

	// Use the key generated for initialize the CA with a dummy handler
	// Create the blind CA API and assign the IP auth function
	ca, err := NewBlindCSP(priv, t.TempDir(), testAuthHandler)
	qt.Assert(t, err, qt.IsNil)

	// Generate a new R point for blinding
	signerR := ca.NewBlindRequestKey()

	// Prepare the hash that will be signed
	hash := ethereum.HashRaw(randomBytes(128))

	// Get a processId (will be used for salting the root key)
	pid := randomBytes(processIDSize)

	// Transform it to big.Int
	m := new(big.Int).SetBytes(hash)

	// Blind the message that is gonna be signed using the R point
	msgBlinded, userSecretData, err := blindsecp256k1.Blind(m, signerR)
	qt.Assert(t, err, qt.IsNil)

	// Perform the blind signature on the blinded message
	blindedSignature, err := ca.SignBlind(signerR, msgBlinded.Bytes(), pid)
	qt.Assert(t, err, qt.IsNil)

	// Unblind the signature
	signature := blindsecp256k1.Unblind(new(big.Int).SetBytes(blindedSignature), userSecretData)

	// Get the serialized signature
	b := signature.Bytes()
	t.Logf("signature %x", b)

	// Recover the serialized signature into signature2 var
	signature2, err := blindsecp256k1.NewSignatureFromBytes(b)
	qt.Assert(t, err, qt.IsNil)
	if !bytes.Equal(signature.Bytes(), signature2.Bytes()) {
		t.Fatalf("signature obtained with NewSignatureFromBytes and signature are different: %x != %x ",
			signature.Bytes(), signature2.Bytes())
	}

	// For verify, use the public key from standard ECDSA (pubdesc)
	t.Logf("blind PubK: %s", ca.PubKeyBlind(pid))

	// From the standard ECDSA pubkey, get the pubkey blind format
	pubKeyECDSA, err := hex.DecodeString(ca.PubKeyECDSA(pid))
	qt.Assert(t, err, qt.IsNil)

	bpub2, err := blindsecp256k1.NewPublicKeyFromECDSA(pubKeyECDSA)
	qt.Assert(t, err, qt.IsNil)

	pubKeyBlind, err := hex.DecodeString(ca.PubKeyBlind(pid))
	qt.Assert(t, err, qt.IsNil)
	if !bytes.Equal(pubKeyBlind, bpub2.Bytes()) {
		t.Fatalf("public key ECDSA and Blindsecp256k1 do not match: %x != %x",
			pubKeyBlind, bpub2.Bytes())
	}
	qt.Assert(t,
		pubKeyBlind,
		qt.DeepEquals,
		bpub2.Bytes(),
	)

	qt.Assert(t,
		blindsecp256k1.Verify(m, signature2, bpub2),
		qt.Equals,
		true,
	)

	// Do the same with a wrong message hash and check verify fails
	hash = ethereum.HashRaw(randomBytes(128))
	qt.Assert(t,
		blindsecp256k1.Verify(new(big.Int).SetBytes(hash), signature2, bpub2),
		qt.Equals,
		false,
	)
}

func testAuthHandler(r *http.Request, m *Message) (bool, string) {
	return true, "hello!"
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return bytes
}
