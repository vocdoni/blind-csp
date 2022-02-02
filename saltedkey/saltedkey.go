package saltedkey

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	blind "github.com/arnaucube/go-blindsecp256k1"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	vocdonicrypto "go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/crypto/saltedkey"
)

const (
	// PrivKeyHexSize is the hexadecimal length of a private key
	PrivKeyHexSize = 64
	// SaltSize is the size of the salt used for derive the new key
	SaltSize = 20
)

// SaltedKey is a wrapper around ECDSA and ECDSA Blind that helps signing
// messages with a known Salt. The Salt is added to the private key curve
// point in order to derive a new deterministic signing key.
// The same operation must be perform on the public key side in order to
// verify the signed messages.
type SaltedKey struct {
	rootKey *big.Int
}

// NewSaltedKey returns an initialized instance of SaltedKey using the private key
// provided in hex format.
func NewSaltedKey(privKey string) (*SaltedKey, error) {
	if len(privKey) != PrivKeyHexSize {
		return nil, fmt.Errorf("private key size is incorrect %d", len(privKey))
	}
	pkb, err := hex.DecodeString(privKey)
	if err != nil {
		return nil, err
	}

	// Check the privKey point is a valid D value
	_, err = ethcrypto.ToECDSA(pkb)
	if err != nil {
		return nil, err
	}
	return &SaltedKey{
		rootKey: new(big.Int).SetBytes(pkb),
	}, nil
}

// SignECDSA returns the signature payload of message (which will be hashed)
// using the provided Salt.
func (sk *SaltedKey) SignECDSA(salt [SaltSize]byte,
	msg []byte) ([]byte, error) {
	esk := new(vocdonicrypto.SignKeys)
	if err := esk.AddHexKey(fmt.Sprintf("%x", sk.rootKey.Bytes())); err != nil {
		return nil, fmt.Errorf("cannot sign ECDSA salted: %w", err)
	}
	// get the bigNumber from salt
	s := new(big.Int).SetBytes(salt[:])
	// add it to the current key, so now we have a new private key (currentPrivKey + n)
	esk.Private.D.Add(esk.Private.D, s)
	// return the signature
	return esk.SignEthereum(msg)
}

// SignBlind returns the signature payload of a blinded message using the provided Salt.
// The Secretk number needs to be also provided.
func (sk *SaltedKey) SignBlind(salt [SaltSize]byte, msgBlinded []byte,
	secretK *big.Int) ([]byte, error) {
	if secretK == nil {
		return nil, fmt.Errorf("secretK is nil")
	}
	s := new(big.Int).SetBytes(salt[:])
	privKey := s.Add(s, sk.rootKey)
	blindPrivKey := blind.PrivateKey(*privKey)
	m := new(big.Int).SetBytes(msgBlinded)
	signature, err := blindPrivKey.BlindSign(m, secretK)
	if err != nil {
		return nil, err
	}
	return signature.Bytes(), nil
}

// BlindPubKey returns the root public key for blind signatures
func (sk *SaltedKey) BlindPubKey() *blind.PublicKey {
	pk := blind.PrivateKey(*sk.rootKey)
	return pk.Public()
}

// ECDSAPubKey returns the root ecdsa public key for plain signatures
func (sk *SaltedKey) ECDSAPubKey() (*ecdsa.PublicKey, error) {
	privK, err := ethcrypto.ToECDSA(sk.rootKey.Bytes())
	if err != nil {
		return nil, err
	}
	return &privK.PublicKey, nil
}

// SaltBlindPubKey returns the salted blind public key of pubKey applying the salt.
func SaltBlindPubKey(pubKey *blind.PublicKey,
	salt [saltedkey.SaltSize]byte) (*blind.PublicKey, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	x, y := ethcrypto.S256().ScalarBaseMult(salt[:])
	s := blind.Point{
		X: x,
		Y: y,
	}
	return (*blind.PublicKey)(pubKey.Point().Add(&s)), nil
}

// SaltECDSAPubKey returns the salted plain public key of pubKey applying the salt.
func SaltECDSAPubKey(pubKey *ecdsa.PublicKey, salt [saltedkey.SaltSize]byte) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	x, y := pubKey.Curve.ScalarBaseMult(salt[:])
	pubKey.X, pubKey.Y = pubKey.Curve.Add(pubKey.X, pubKey.Y, x, y)
	return ethcrypto.FromECDSAPub(pubKey), nil
}
