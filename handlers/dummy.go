package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/log"
)

// DummyHandler is a handler for testing that returns always true
type DummyHandler struct{}

// Init does nothing
func (dh *DummyHandler) Init(r *httprouter.HTTProuter, baseURL string, opts ...string) error {
	return nil
}

// GetName returns the name of the handler
func (dh *DummyHandler) Name() string {
	return "dummy"
}

// Info returns the handler options and required auth steps.
func (dh *DummyHandler) Info() *types.Message {
	return &types.Message{
		Title:    "dummy handler",
		AuthType: "auth",
		SignType: types.AllSignatures,
		AuthSteps: []*types.AuthField{
			{Title: "Name", Type: "text"},
		},
	}
}

// Indexer takes a unique user identifier and returns the list of processIDs where
// the user is elegible for participation. This is a helper function that might not
// be implemented (depends on the handler use case).
func (dh *DummyHandler) Indexer(userID types.HexBytes) []types.Election {
	return nil
}

// Auth is the handler for the dummy handler
func (dh *DummyHandler) Auth(r *http.Request,
	ca *types.Message, pid types.HexBytes, signType string, step int,
) types.AuthResponse {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	log.Infof("new user registered with ip %s", ipaddr)
	return types.AuthResponse{
		Success:   true,
		Response:  []string{fmt.Sprintf("welcome to process %s!", pid)},
		AuthToken: nil, // make authToken nil explicit, so the auth process is considered ended
	}
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
