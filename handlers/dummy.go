package handlers

import (
	"net/http"
	"strings"

	"github.com/vocdoni/blind-ca/blindca"
	"go.vocdoni.io/dvote/log"
)

// DummyHandler is a handler for testing that returns always true
type DummyHandler struct {
}

// Auth is the handler for the dummy handler
func (dh *DummyHandler) Auth(r *http.Request, ca *blindca.BlindCA) (bool, string) {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	log.Infof("new user registered with ip %s", ipaddr)
	return true, "welcome!"
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (dh *DummyHandler) RequireCertificate() bool {
	return false
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer (optional).
func (dh *DummyHandler) CertificateCheck(subject []byte) bool {
	return true
}

// HardcodedCertificate returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (dh *DummyHandler) HardcodedCertificate() []byte {
	return nil
}
