package csp

import (
	"crypto/rand"
	"fmt"
	"math/big"

	blind "github.com/arnaucube/go-blindsecp256k1"
	"github.com/vocdoni/blind-csp/saltedkey"
	"go.vocdoni.io/dvote/log"
)

// PubKeyBlind returns the public key of the blind CSP signer.
// If processID is nil, returns the root public key.
// If processID is not nil, returns the salted public key.
func (csp *BlindCSP) PubKeyBlind(processID []byte) string {
	if processID == nil {
		return fmt.Sprintf("%x", csp.signer.BlindPubKey())
	}
	var salt [saltedkey.SaltSize]byte
	copy(salt[:], processID[:saltedkey.SaltSize])
	pk, err := saltedkey.SaltBlindPubKey(csp.signer.BlindPubKey(), salt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", pk.Bytes())
}

// PubKeyECDSA returns the public key of the plain CSP signer
// If processID is nil, returns the root public key.
// If processID is not nil, returns the salted public key.
func (csp *BlindCSP) PubKeyECDSA(processID []byte) string {
	k, err := csp.signer.ECDSAPubKey()
	if err != nil {
		return ""
	}
	if processID == nil {
		return fmt.Sprintf("%x", k)
	}
	var salt [saltedkey.SaltSize]byte
	copy(salt[:], processID[:saltedkey.SaltSize])
	pk, err := saltedkey.SaltECDSAPubKey(k, salt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", pk)
}

// NewBlindRequestKey generates a new request key for blinding a content on the client side.
// It returns SignerR and SignerQ values.
func (csp *BlindCSP) NewBlindRequestKey() (*blind.Point, error) {
	k, signerR, err := blind.NewRequestParameters()
	if err != nil {
		log.Warn(err)
		return nil, err
	}
	index := signerR.X.String() + signerR.Y.String()
	if err := csp.addKey(index, k); err != nil {
		log.Warn(err)
		return nil, err
	}
	if k.Uint64() == 0 {
		return nil, fmt.Errorf("k can not be 0, k: %s", k)
	}
	return signerR, nil
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
func (csp *BlindCSP) SignECDSA(token, msg []byte, processID []byte) ([]byte, error) {
	if k, err := csp.getKey(string(token)); err != nil || k == nil {
		return nil, fmt.Errorf("token not found")
	}
	defer func() {
		if err := csp.delKey(string(token)); err != nil {
			log.Warn(err)
		}
	}()
	var salt [saltedkey.SaltSize]byte
	copy(salt[:], processID[:saltedkey.SaltSize])
	return csp.signer.SignECDSA(salt, msg)
}

// SignBlind performs a blind signature over hash. Also checks if R point is valid
// and removes it from the local storage if err=nil.
func (csp *BlindCSP) SignBlind(signerR *blind.Point, hash, processID []byte) ([]byte, error) {
	key := signerR.X.String() + signerR.Y.String()
	k, err := csp.getKey(key)
	if k == nil || err != nil {
		return nil, fmt.Errorf("unknown R point")
	}
	var salt [saltedkey.SaltSize]byte
	copy(salt[:], processID[:saltedkey.SaltSize])
	signature, err := csp.signer.SignBlind(salt, hash, k)
	if err != nil {
		return nil, err
	}
	if err := csp.delKey(key); err != nil {
		return nil, err
	}
	return signature, nil
}

// SharedKey performs a signature over processId which might be used as shared key
// for all users belonging to the same process.
func (csp *BlindCSP) SharedKey(processID []byte) ([]byte, error) {
	var salt [saltedkey.SaltSize]byte
	copy(salt[:], processID[:saltedkey.SaltSize])
	return csp.signer.SignECDSA(salt, processID)
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
