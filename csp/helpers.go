package csp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	blind "github.com/arnaucube/go-blindsecp256k1"
	"go.vocdoni.io/dvote/log"
)

// PubKeyBlind returns the public key of the blind CA signer
func (csp *BlindCSP) PubKeyBlind() string {
	return hex.EncodeToString(csp.blindKey.Public().Bytes())
}

// NewBlindRequestKey generates a new request key for blinding a content on the client side.
// It returns SignerR and SignerQ values.
func (csp *BlindCSP) NewBlindRequestKey() *blind.Point {
	k, signerR := blind.NewRequestParameters()
	index := signerR.X.String() + signerR.Y.String()
	if err := csp.addKey(index, k); err != nil {
		log.Warn(err)
		return nil
	}
	if k.Uint64() == 0 {
		return nil
	}
	return signerR
}

// NewRequestKey generates a new request key for blinding a content on the client side.
// It returns SignerR and SignerQ values.
func (csp *BlindCSP) NewRequestKey() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	if err := csp.addKey(string(b), new(big.Int).SetUint64(0)); err != nil {
		log.Warn(err)
		return nil
	}
	return b
}

// SignECDSA performs a blind signature over hash(msg). Also checks if token is valid
// and removes it from the local storage.
func (csp *BlindCSP) SignECDSA(token, msg []byte) ([]byte, error) {
	if k, err := csp.getKey(string(token)); err != nil || k == nil {
		return nil, fmt.Errorf("token not found")
	}
	defer func() {
		if err := csp.delKey(string(token)); err != nil {
			log.Warn(err)
		}
	}()
	return csp.ecdsaKey.Sign(msg)
}

// SignBlind performs a blind signature over hash. Also checks if R point is valid
// and removes it from the local storage if err=nil.
func (csp *BlindCSP) SignBlind(signerR *blind.Point, hash []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(hash)
	key := signerR.X.String() + signerR.Y.String()
	k, err := csp.getKey(key)
	if k == nil || err != nil {
		return nil, fmt.Errorf("unknown R point")
	}
	signature, err := csp.blindKey.BlindSign(m, k)
	if err != nil {
		return nil, err
	}
	if err := csp.delKey(key); err != nil {
		return nil, err
	}
	return signature.Bytes(), nil
}

// SyncMap helpers
func (csp *BlindCSP) addKey(index string, point *big.Int) error {
	csp.keysLock.Lock()
	defer csp.keysLock.Unlock()
	tx := csp.keys.WriteTx()
	defer tx.Discard()
	if err := tx.Set([]byte(index), point.Bytes()); err != nil {
		log.Error(err)
	}
	return tx.Commit()
}

func (csp *BlindCSP) delKey(index string) error {
	csp.keysLock.Lock()
	defer csp.keysLock.Unlock()
	tx := csp.keys.WriteTx()
	defer tx.Discard()
	if err := tx.Delete([]byte(index)); err != nil {
		log.Error(err)
	}
	return tx.Commit()
}

func (csp *BlindCSP) getKey(index string) (*big.Int, error) {
	csp.keysLock.RLock()
	defer csp.keysLock.RUnlock()
	tx := csp.keys.WriteTx()
	defer tx.Discard()
	p, err := tx.Get([]byte(index))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(p), nil
}
