package handlers

import (
	"net/http"
	"strings"

	"github.com/vocdoni/blind-csp/csp"
	"github.com/vocdoni/blind-csp/handlers/idcathandler"
	"github.com/vocdoni/blind-csp/handlers/rsahandler"
)

// AuthHandler is the interface that all CSP handlers should implement.
// The Auth method must return either the request is valid or not.
// The current signatureType supported are:
//  1. ecdsa: performs a plain ECDSA signature over the payload provided by the user
//  2. blind: performs a blind ECDSA signature over the payload provided by the user
//  3. sharedkey: performs a plain ECDSA signature over hash(processId)
type AuthHandler interface {
	Init(opts ...string) error
	GetName() string
	Auth(r *http.Request, ca *csp.Message,
		processID []byte, signatureType string) (bool, string)
	RequireCertificate() bool
	Certificates() [][]byte
	CertificateCheck(subject []byte) bool
}

// Handlers contains the list of available handlers
var Handlers = map[string]AuthHandler{
	"dummy":        &DummyHandler{},
	"uniqueIp":     &IpaddrHandler{},
	"idCat":        &idcathandler.IDcatHandler{ForTesting: false},
	"idCatTesting": &idcathandler.IDcatHandler{ForTesting: true},
	"rsa":          &rsahandler.RsaHandler{},
}

// HandlersList returns a human friendly string with the list of available handlers
func HandlersList() string {
	var h string
	for k := range Handlers {
		h += k + " "
	}
	return strings.TrimRight(h, " ")
}
