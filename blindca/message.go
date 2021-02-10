package blindca

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"path/filepath"
	"sync"

	blind "github.com/arnaucube/go-blindsecp256k1"
	"github.com/vocdoni/multirpc/router"
	"github.com/vocdoni/multirpc/transports"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

const (
	// PrivKeyHexSize is the hexadecimal length of a private key
	PrivKeyHexSize = 64

	// RandomTokenSize is the maximum size of the random token for auth queries
	RandomTokenSize = 32
)

// BlindCAauthFunc is the function type required for performing an authentication
// via callback handler.
type BlindCAauthFunc = func(r *http.Request, msg *BlindCA) (bool, string)

// BlindCA blind signature API service for certification authorities
type BlindCA struct {
	ID            string          `json:"request"`
	Method        string          `json:"method,omitempty"`
	AuthData      []string        `json:"authData,omitempty"` // reserved for the auth handler
	Reply         string          `json:"reply,omitempty"`    // reserved for the auth handler
	Timestamp     int32           `json:"timestamp"`
	OK            bool            `json:"ok"`
	Error         string          `json:"error,omitempty"`
	Token         router.HexBytes `json:"token,omitempty"`
	SignatureType string          `json:"signatureType,omitempty"`
	MessageHash   router.HexBytes `json:"messageHash,omitempty"`
	Message       []byte          `json:"message,omitempty"`
	CAsignature   router.HexBytes `json:"caSignature,omitempty"`
	AuthCallback  BlindCAauthFunc `json:"-"`
	ecdsaKey      *ethereum.SignKeys
	blindKey      blind.PrivateKey
	keys          *db.BadgerDB
	keysLock      sync.RWMutex
}

// Init initializes the CA API with a private key (64 digits hexadecimal string)
// and a callback authorization function.
func (ca *BlindCA) Init(privKey string, callback BlindCAauthFunc, dataDir string) error {
	if len(privKey) != PrivKeyHexSize {
		return fmt.Errorf("private key size is incorrect %d", len(privKey))
	}
	pkb, err := hex.DecodeString(privKey)
	if err != nil {
		return err
	}

	// ECDSA signer
	ca.ecdsaKey = new(ethereum.SignKeys)
	if err := ca.ecdsaKey.AddHexKey(privKey); err != nil {
		return err
	}

	// Blind signer
	a := new(big.Int).SetBytes(pkb)
	ca.blindKey = blind.PrivateKey(*a)
	ca.AuthCallback = callback

	// Storage
	ca.keys, err = db.NewBadgerDB(filepath.Clean(dataDir))
	return err
}

// PubKeyBlind returns the public key of the blind CA signer
func (ca *BlindCA) PubKeyBlind() string {
	return hex.EncodeToString(ca.blindKey.Public().Bytes())
}

// NewBlindRequestKey generates a new request key for blinding a content on the client side.
// It returns SignerR and SignerQ values.
func (ca *BlindCA) NewBlindRequestKey() *blind.Point {
	k, signerR := blind.NewRequestParameters()
	index := signerR.X.String() + signerR.Y.String()
	ca.addKey(index, k)
	if k.Uint64() == 0 {
		return nil
	}
	return signerR
}

// NewRequestKey generates a new request key for blinding a content on the client side.
// It returns SignerR and SignerQ values.
func (ca *BlindCA) NewRequestKey() []byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	ca.addKey(string(b), new(big.Int).SetUint64(0))
	return b
}

// SignECDSA performs a blind signature over hash(msg). Also checks if token is valid
// and removes it from the local storage.
func (ca *BlindCA) SignECDSA(token, msg []byte) ([]byte, error) {
	if k := ca.getKey(string(token)); k == nil {
		return nil, fmt.Errorf("token not found")
	}
	defer ca.delKey(string(token))
	return ca.ecdsaKey.Sign(msg)
}

// SignBlind performs a blind signature over hash. Also checks if R point is valid
// and removes it from the local storage if err=nil.
func (ca *BlindCA) SignBlind(signerR *blind.Point, hash []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(hash)
	key := signerR.X.String() + signerR.Y.String()
	k := ca.getKey(key)
	if k == nil {
		return nil, fmt.Errorf("unknown R point")
	}
	signature, err := ca.blindKey.BlindSign(m, k)
	if err != nil {
		return nil, err
	}
	ca.delKey(key)
	return signature.Bytes(), nil
}

// SyncMap helpers
func (ca *BlindCA) addKey(index string, point *big.Int) {
	ca.keysLock.Lock()
	defer ca.keysLock.Unlock()
	if err := ca.keys.Put([]byte(index), point.Bytes()); err != nil {
		log.Error(err)
	}
}

func (ca *BlindCA) delKey(index string) {
	ca.keysLock.Lock()
	defer ca.keysLock.Unlock()
	if err := ca.keys.Del([]byte(index)); err != nil {
		log.Error(err)
	}
}

func (ca *BlindCA) getKey(index string) *big.Int {
	ca.keysLock.RLock()
	defer ca.keysLock.RUnlock()
	p, err := ca.keys.Get([]byte(index))
	if err != nil {
		return nil
	}
	return new(big.Int).SetBytes(p)
}

// transports.MessageAPI methods

// GetID returns the ID for de request
func (ca *BlindCA) GetID() string {
	return ca.ID
}

// SetID sets a request ID
func (ca *BlindCA) SetID(id string) {
	ca.ID = id
}

// SetTimestamp sets the timestamp
func (ca *BlindCA) SetTimestamp(ts int32) {
	ca.Timestamp = ts
}

// SetError sets an error message
func (ca *BlindCA) SetError(e string) {
	ca.OK = false
	ca.Error = e
}

// GetMethod returns the method
func (ca *BlindCA) GetMethod() string {
	return ca.Method
}

// NewAPI is a required function for returning the implemented interface transports.MessageAPI
// This function is used by the router in order to fetch the specific type.
func (ca *BlindCA) NewAPI() transports.MessageAPI {
	return &BlindCA{}
}
