package blindca

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	blind "github.com/arnaucube/go-blindsecp256k1"
	"github.com/vocdoni/multirpc/router"
	"github.com/vocdoni/multirpc/transports"
)

// PrivKeyHexSize is the hexadecimal length of a private key
const PrivKeyHexSize = 64

// BlindCAauthFunc is the function type required for performing an authentication
// via callback handler.
type BlindCAauthFunc = func(r *http.Request, msg *BlindCA) bool

// BlindCA blind signature API service for certification authorities
type BlindCA struct {
	ID             string          `json:"request"`
	Method         string          `json:"method,omitempty"`
	AuthData       []string        `json:"authData,omitempty"` // reserved for the auth handler
	Reply          string          `json:"reply,omitempty"`    // reserved for the auth handler
	Timestamp      int32           `json:"timestamp"`
	OK             bool            `json:"ok"`
	Error          string          `json:"error,omitempty"`
	SignerR        *blind.Point    `json:"signerR,omitempty"`
	MessageHash    router.HexBytes `json:"messageHash,omitempty"`
	BlindSignature router.HexBytes `json:"blindSignature,omitempty"`

	AuthCallback BlindCAauthFunc `json:"-"`
	sk           blind.PrivateKey
	keys         sync.Map
}

// Init initializes the CA API with a private key (64 digits hexadecimal string)
// and a callback authorization function.
func (ca *BlindCA) Init(privKey string, callback BlindCAauthFunc) error {
	if len(privKey) != PrivKeyHexSize {
		return fmt.Errorf("private key size is incorrect %d", len(privKey))
	}
	pkb, err := hex.DecodeString(privKey)
	if err != nil {
		return err
	}
	a := new(big.Int).SetBytes(pkb)
	ca.sk = blind.PrivateKey(*a)
	ca.AuthCallback = callback
	return nil
}

// NewKey creates a new random key
func NewKey() string {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	bi := new(big.Int).SetBytes(b[:])
	return hex.EncodeToString(new(big.Int).Mod(bi, blind.N).Bytes())
}

// PubKey returns the public key of the blind CA signer
func (ca *BlindCA) PubKey() string {
	pubk, err := ca.sk.Public().MarshalJSON()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(pubk)
}

// NewRequestKey generates a new request key for blinding a content on the client side.
// It returns SignerR and SignerQ values.
func (ca *BlindCA) NewRequestKey() *blind.Point {
	k, signerR := blind.NewRequestParameters()
	index := signerR.X.String() + signerR.Y.String()
	ca.addKey(index, k)
	return signerR
}

// Sign performs a blind signature over hash.
func (ca *BlindCA) Sign(signerR *blind.Point, hash []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(hash)
	key := signerR.X.String() + signerR.Y.String()
	k := ca.getKey(key)
	if k == nil {
		return nil, fmt.Errorf("unknown R point")
	}
	sBlind := ca.sk.BlindSign(m, k)
	ca.delKey(key)
	return sBlind.Bytes(), nil
}

// SyncMap helpers
func (ca *BlindCA) addKey(index string, point *big.Int) {
	ca.keys.Store(index, point)
}

func (ca *BlindCA) delKey(index string) {
	ca.keys.Delete(index)
}

func (ca *BlindCA) getKey(index string) *big.Int {
	p, ok := ca.keys.Load(index)
	if !ok {
		return nil
	}
	return p.(*big.Int)
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
