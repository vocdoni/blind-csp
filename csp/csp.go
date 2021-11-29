package csp

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"

	blind "github.com/arnaucube/go-blindsecp256k1"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/bearerstdapi"
	"go.vocdoni.io/dvote/log"
)

const (
	// PrivKeyHexSize is the hexadecimal length of a private key
	PrivKeyHexSize = 64

	// RandomTokenSize is the maximum size of the random token for auth queries
	RandomTokenSize = 32
)

// BlindCSPauthFunc is the function type required for performing an authentication
// via callback handler.
type BlindCSPauthFunc = func(r *http.Request, msg *Message) (bool, string)

// BlindCSP is the blind signature API service for certification authorities
type BlindCSP struct {
	AuthCallback BlindCSPauthFunc
	router       *httprouter.HTTProuter
	api          *bearerstdapi.BearerStandardAPI
	ecdsaKey     *ethereum.SignKeys
	blindKey     blind.PrivateKey
	keys         db.Database
	keysLock     sync.RWMutex
}

// NewBlindCSP creates and initializes the CSP API with a private key (64 digits hexadecimal string)
// and a custom callback authorization function.
func NewBlindCSP(privKey, dataDir string, callback BlindCSPauthFunc) (*BlindCSP, error) {
	if len(privKey) != PrivKeyHexSize {
		return nil, fmt.Errorf("private key size is incorrect %d", len(privKey))
	}
	pkb, err := hex.DecodeString(privKey)
	if err != nil {
		return nil, err
	}

	csp := new(BlindCSP)
	csp.AuthCallback = callback

	// ECDSA signer
	csp.ecdsaKey = new(ethereum.SignKeys)
	if err := csp.ecdsaKey.AddHexKey(privKey); err != nil {
		return nil, err
	}

	// Blind signer
	a := new(big.Int).SetBytes(pkb)
	csp.blindKey = blind.PrivateKey(*a)

	// Storage
	log.Debugf("initializing persistent storage on %s", dataDir)
	csp.keys, err = metadb.New(db.TypePebble, dataDir)

	return csp, err
}

// ServeAPI registers the API handlers into the router under the baseRoute path
func (csp *BlindCSP) ServeAPI(r *httprouter.HTTProuter, baseRoute string) error {
	if len(baseRoute) == 0 || baseRoute[0] != '/' {
		return fmt.Errorf("invalid base route (%s), it must start with /", baseRoute)
	}
	// Remove trailing slash
	if len(baseRoute) > 1 {
		baseRoute = strings.TrimSuffix(baseRoute, "/")
	}
	if r == nil {
		return fmt.Errorf("router is nil")
	}
	// Initialize API
	csp.router = r
	var err error
	csp.api, err = bearerstdapi.NewBearerStandardAPI(csp.router, baseRoute)
	if err != nil {
		return err
	}
	return csp.registerHandlers()
}
