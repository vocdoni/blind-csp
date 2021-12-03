package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vocdoni/blind-csp/csp"
	"go.vocdoni.io/dvote/log"
)

// DummyHandler is a handler for testing that returns always true
type DummyHandler struct{}

// Init does nothing
func (dh *DummyHandler) Init(opts ...string) error {
	return nil
}

// GetName returns the name of the handler
func (dh *DummyHandler) GetName() string {
	return "dummy"
}

// Auth is the handler for the dummy handler
func (dh *DummyHandler) Auth(r *http.Request,
	ca *csp.Message, pid []byte, st string) (bool, string) {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	log.Infof("new user registered with ip %s", ipaddr)
	return true, fmt.Sprintf("welcome to process %x!", pid)
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

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (dh *DummyHandler) Certificates() [][]byte {
	return nil
}
