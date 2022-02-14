package saltedkey

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"

	blind "github.com/arnaucube/go-blindsecp256k1"
	qt "github.com/frankban/quicktest"
	"go.vocdoni.io/dvote/crypto/ethereum"
)

func TestECDSAsaltedKey(t *testing.T) {
	privHex := fmt.Sprintf("%x", randomBytes(32))
	sk, err := NewSaltedKey(privHex)
	qt.Assert(t, err, qt.IsNil)

	salt := [SaltSize]byte{}
	copy(salt[:], randomBytes(20))
	msg := []byte("hello world!")

	signature, err := sk.SignECDSA(salt, msg)
	qt.Assert(t, err, qt.IsNil)

	saltAddr, err := ethereum.AddrFromSignature(msg, signature)
	qt.Assert(t, err, qt.IsNil)

	signingKeys := ethereum.NewSignKeys()
	signingKeys.AddAuthKey(saltAddr)

	ok, _, err := signingKeys.VerifySender(msg, signature)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, ok, qt.IsTrue)
}

func TestBlindsaltedKey(t *testing.T) {
	privHex := fmt.Sprintf("%x", randomBytes(32))
	sk, err := NewSaltedKey(privHex)
	qt.Assert(t, err, qt.IsNil)

	salt := [SaltSize]byte{}
	copy(salt[:], randomBytes(20))
	msgHash := ethereum.HashRaw([]byte("hello world!"))

	// Server: generate a new secretK and R (R is required for blinding and K for signing)
	k, signerR, err := blind.NewRequestParameters()
	qt.Assert(t, err, qt.IsNil)

	// Client: blinds the message with R (from server). Keeps userSecretData for unblinding
	msgBlinded, userSecretData, err := blind.Blind(new(big.Int).SetBytes(msgHash), signerR)
	qt.Assert(t, err, qt.IsNil)

	// Server: performs the signature with the commont salt using secretK
	blindedSignature, err := sk.SignBlind(salt, msgBlinded.Bytes(), k)
	qt.Assert(t, err, qt.IsNil)

	// Client: unblind the signature
	signature := blind.Unblind(new(big.Int).SetBytes(blindedSignature), userSecretData)

	// Any: verifies the signature (salting previously the pubKey with the common salt)
	saltedPubKey, err := SaltBlindPubKey(sk.BlindPubKey(), salt)
	qt.Assert(t, err, qt.IsNil)
	valid := blind.Verify(new(big.Int).SetBytes(msgHash), signature, saltedPubKey)
	qt.Assert(t, valid, qt.IsTrue)
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return bytes
}
