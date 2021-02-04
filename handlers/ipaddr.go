package handlers

import (
	"net/http"
	"strings"
	"sync"

	"github.com/vocdoni/blind-ca/blindca"
	"go.vocdoni.io/dvote/log"
)

// IpaddrHandler is a handler that allows only 1 registration for IP
type IpaddrHandler struct {
	kv sync.Map
}

// Auth is the handler for the ipaddr handler
func (ih *IpaddrHandler) Auth(r *http.Request, ca *blindca.BlindCA) (bool, string) {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	if len(ipaddr) == 0 {
		log.Warnf("cannot get ip from request: %s", r.RemoteAddr)
		return false, "cannot get IP from request"
	}
	if _, ok := ih.kv.Load(ipaddr); ok {
		log.Warnf("ip %s already registered", ipaddr)
		return false, "already registered"
	}
	ih.kv.Store(ipaddr, nil)
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

// HardcodedCertificate returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *IpaddrHandler) HardcodedCertificate() []byte {
	return nil
}
