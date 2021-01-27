package blindca

import (
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
	signer.Generate()
	pub, priv := signer.HexString()
	t.Logf("using pubkey:%s privkey:%s", pub, priv)

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

	// Perform the blind signature on the blind message
	blindedSignature, err := ca.Sign(signerR, msgBlinded.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// Unblind the signature and verify it
	signature := blindsecp256k1.Unblind(new(big.Int).SetBytes(blindedSignature), m, userSecretData)
	if !blindsecp256k1.Verify(m, signature, ca.sk.Public()) {
		t.Errorf("blindsecp256k1 cannot verify the signature")
	}

	b, _ := signature.MarshalJSON()
	t.Logf("signature %x", b)

	// Do the same with a wrong message hash and check verify fails
	hash = ethereum.HashRaw(randomBytes(128))
	m = new(big.Int).SetBytes(hash)
	if blindsecp256k1.Verify(m, signature, ca.sk.Public()) {
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
