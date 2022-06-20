package handlers

import (
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/log"
)

// IpaddrHandler is a handler that allows only 1 registration for IP
type IpaddrHandler struct {
	kv       db.Database
	keysLock sync.RWMutex
}

func (ih *IpaddrHandler) addKey(index, value []byte) {
	ih.keysLock.Lock()
	defer ih.keysLock.Unlock()
	tx := ih.kv.WriteTx()
	defer tx.Discard()
	if err := tx.Set(index, value); err != nil {
		log.Error(err)
	}
	if err := tx.Commit(); err != nil {
		log.Error(err)
	}
}

func (ih *IpaddrHandler) exist(index []byte) bool {
	ih.keysLock.RLock()
	defer ih.keysLock.RUnlock()
	tx := ih.kv.WriteTx()
	defer tx.Discard()
	_, err := tx.Get(index)
	return err == nil
}

// GetName returns the name of the handler
func (ih *IpaddrHandler) GetName() string {
	return "uniqueIp"
}

// Init initializes the handler.
// Takes one argument for persistent data directory.
func (ih *IpaddrHandler) Init(opts ...string) (err error) {
	ih.kv, err = metadb.New(db.TypePebble, filepath.Clean(opts[0]))
	return err
}

// Auth is the handler for the ipaddr handler
func (ih *IpaddrHandler) Auth(r *http.Request,
	ca *types.Message, pid types.HexBytes, signType string, step int) AuthResponse {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	if len(ipaddr) == 0 {
		log.Warnf("cannot get ip from request: %s", r.RemoteAddr)
		return AuthResponse{Response: []string{"cannot get IP from request"}}
	}
	if signType == types.SignatureTypeSharedKey {
		return AuthResponse{}
	}
	if ih.exist([]byte(ipaddr)) {
		log.Warnf("ip %s already registered", ipaddr)
		return AuthResponse{Response: []string{"already registered"}}
	}
	ih.addKey([]byte(ipaddr), nil)
	log.Infof("new user registered with ip %s", ipaddr)
	return AuthResponse{}
}

// Info returns the handler options and required auth steps.
func (ih *IpaddrHandler) Info() *types.Message {
	return &types.Message{
		Title:     "unique IP address",
		AuthType:  "blind",
		AuthSteps: []*types.AuthField{},
	}
}

// Indexer takes a unique user identifier and returns the list of processIDs where
// the user is elegible for participation. This is a helper function that might not
// be implemented (depends on the handler use case).
func (ih *IpaddrHandler) Indexer(userID types.HexBytes) []*types.HexBytes {
	return nil
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (ih *IpaddrHandler) RequireCertificate() bool {
	return false
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer (optional).
func (ih *IpaddrHandler) CertificateCheck(subject []byte) bool {
	return true
}

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *IpaddrHandler) Certificates() [][]byte {
	return nil
}
