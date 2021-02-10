package handlers

import (
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vocdoni/blind-ca/blindca"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

// IpaddrHandler is a handler that allows only 1 registration for IP
type IpaddrHandler struct {
	kv       *db.BadgerDB
	keysLock sync.RWMutex
}

func (ih *IpaddrHandler) addKey(index, value []byte) {
	ih.keysLock.Lock()
	defer ih.keysLock.Unlock()
	if err := ih.kv.Put(index, value); err != nil {
		log.Error(err)
	}
}

func (ih *IpaddrHandler) exist(index []byte) bool {
	ih.keysLock.RLock()
	defer ih.keysLock.RUnlock()
	_, err := ih.kv.Get(index)
	return err == nil
}

// GetName returns the name of the handler
func (ih *IpaddrHandler) GetName() string {
	return "uniqueIp"
}

// Init initializes the handler.
// Takes one argument for persistent data directory.
func (ih *IpaddrHandler) Init(opts ...string) (err error) {
	ih.kv, err = db.NewBadgerDB(filepath.Clean(opts[0]))
	return err
}

// Auth is the handler for the ipaddr handler
func (ih *IpaddrHandler) Auth(r *http.Request, ca *blindca.BlindCA) (bool, string) {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	if len(ipaddr) == 0 {
		log.Warnf("cannot get ip from request: %s", r.RemoteAddr)
		return false, "cannot get IP from request"
	}
	if ih.exist([]byte(ipaddr)) {
		log.Warnf("ip %s already registered", ipaddr)
		return false, "already registered"
	}
	ih.addKey([]byte(ipaddr), nil)
	log.Infof("new user registered with ip %s", ipaddr)
	return true, ""
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

// Certificate returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *IpaddrHandler) Certificate() []byte {
	return nil
}
