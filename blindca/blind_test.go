package blindca

import (
	"bytes"
	"io"
	"math/big"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/arnaucube/go-blindsecp256k1"
	"go.vocdoni.io/dvote/crypto/ethereum"
)

var randReader = rand.New(rand.NewSource(time.Now().UnixNano()))

func TestBlindCA(t *testing.T) {
	// Create the blind CA API and assign the IP auth function
	ca := new(BlindCA)

	// Generate a new signing key
	signer := ethereum.SignKeys{}
	if err := signer.Generate(); err != nil {
		t.Fatal(err)
	}
	_, priv := signer.HexString()
	pubdesc, err := ethereum.DecompressPubKey(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("using pubkey:%x privkey:%s", pubdesc, priv)

	// Use the key generate for initialize the CAAPI
	if err := ca.Init(priv, testAuthHandler); err != nil {
		t.Fatal(err)
	}

	// Generate a new R point for blinding
	signerR := ca.NewRequestKey()

	// Prepare the hash that will be signed
	hash := ethereum.HashRaw(randomBytes(128))

	// Transform it to big.Int
	m := new(big.Int).SetBytes(hash)

	// Blind the message that is gonna be signed using the R point
	msgBlinded, userSecretData := blindsecp256k1.Blind(m, signerR)

	// Perform the blind signature on the blinded message
	blindedSignature, err := ca.Sign(signerR, msgBlinded.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Unblind the signature
	signature := blindsecp256k1.Unblind(new(big.Int).SetBytes(blindedSignature), m, userSecretData)

	// Get the serialized signature
	b := signature.Bytes()
	t.Logf("signature %x", b)

	// Recover the serialized signature into signature2 var
	signature2, err := blindsecp256k1.NewSignatureFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signature.Bytes(), signature2.Bytes()) {
		t.Fatalf("signature obtained with NewSignatureFromBytes and signature are different: %x != %x ",
			signature.Bytes(), signature2.Bytes())
	}

	// For verify, use the public key from standard ECDSA (pubdesc)
	t.Logf("blind PubK: %x", ca.sk.Public().Bytes())

	// From the standard ECDSA pubkey, get the pubkey blind format
	bpub2, err := blindsecp256k1.NewPublicKeyFromECDSA(pubdesc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca.sk.Public().Bytes(), bpub2.Bytes()) {
		t.Fatalf("public key ECDSA and Blindsecp256k1 do not match: %x != %x", ca.sk.Public().Bytes(), bpub2.Bytes())
	}

	// Verity the signature
	if !blindsecp256k1.Verify(m, signature2, bpub2) {
		t.Errorf("blindsecp256k1 cannot verify the signature")
	}

	// Do the same with a wrong message hash and check verify fails
	hash = ethereum.HashRaw(randomBytes(128))
	if blindsecp256k1.Verify(new(big.Int).SetBytes(hash), signature2, bpub2) {
		t.Errorf("blindsecp256k1 has verified the signature, but it should fail")
	}

}

func testAuthHandler(r *http.Request, m *BlindCA) bool {
	return true
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(randReader, bytes); err != nil {
		panic(err)
	}
	return bytes
}
