package csp

import (
	"fmt"
	"strings"
	"sync"

	"github.com/vocdoni/blind-csp/handlers"
	"github.com/vocdoni/blind-csp/saltedkey"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/apirest"
	"go.vocdoni.io/dvote/log"
)

const (
	// PrivKeyHexSize is the hexadecimal length of a private key
	PrivKeyHexSize = 64

	// RandomTokenSize is the maximum size of the random token for auth queries
	RandomTokenSize = 32
)

// BlindCSP is the blind signature API service for certification authorities
type BlindCSP struct {
	callbacks *BlindCSPcallbacks
	router    *httprouter.HTTProuter
	api       *apirest.API
	signer    *saltedkey.SaltedKey
	keys      db.Database
	keysLock  sync.RWMutex
}

type BlindCSPcallbacks struct {
	Auth    handlers.AuthFunc
	Info    handlers.InfoFunc
	Indexer handlers.IndexerFunc
}

// NewBlindCSP creates and initializes the CSP API with a private key (64 digits hexadecimal string)
// and a custom callback authorization function.
func NewBlindCSP(privKey, dataDir string, handlerCallbacks BlindCSPcallbacks) (*BlindCSP, error) {
	if len(privKey) != PrivKeyHexSize {
		return nil, fmt.Errorf("private key size is incorrect %d", len(privKey))
	}
	csp := new(BlindCSP)
	csp.callbacks = &handlerCallbacks
	var err error
	// ECDSA/Blind signer
	if csp.signer, err = saltedkey.NewSaltedKey(privKey); err != nil {
		return nil, err
	}

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
	csp.api, err = apirest.NewAPI(csp.router, baseRoute)
	if err != nil {
		return err
	}
	return csp.registerHandlers()
}
