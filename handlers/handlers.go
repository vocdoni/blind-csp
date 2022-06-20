package handlers

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/types"
)

// AuthFunc is the function type required for performing an authentication
// via callback handler.
type AuthFunc = func(
	httpRequest *http.Request,
	message *types.Message,
	electionID types.HexBytes,
	signaturetype string,
	authStep int) AuthResponse

// InfoFunc is the function type required for providing the handler options
// and description via callback handler.
type InfoFunc = func() *types.Message

// IndexerFunc is the function type used for providing the user with the list of
// processes where its participation is allowed.
type IndexerFunc = func(userID types.HexBytes) []types.HexBytes

// AuthHandler is the interface that all CSP handlers should implement.
// The Auth method must return either the request is valid or not.
// The current signatureType supported are:
//  1. ecdsa: performs a plain ECDSA signature over the payload provided by the user
//  2. blind: performs a blind ECDSA signature over the payload provided by the user
//  3. sharedkey: performs a plain ECDSA signature over hash(processId)
type AuthHandler interface {
	Init(opts ...string) error
	GetName() string
	Auth(httpRequest *http.Request,
		message *types.Message,
		electionID types.HexBytes,
		signatureType string,
		step int) AuthResponse
	RequireCertificate() bool
	Certificates() [][]byte
	CertificateCheck(subject []byte) bool
	Info() *types.Message
	Indexer(userID types.HexBytes) []types.HexBytes
}

// AuthResponse is the type returned by Auth methods on the AuthHandler interface.
// If success true and AuthToken is nil, authentication process is considered finished,
// and the CSP signature is provided to the user.
type AuthResponse struct {
	Success   bool       // Either the authentication step is success or not
	Response  []string   // Response can be used by the handler to provide arbitrary data to the client
	AuthToken *uuid.UUID // Only if there is a next step
}

func (a *AuthResponse) String() string {
	if len(a.Response) == 0 {
		return ""
	}
	var buf strings.Builder
	for i, r := range a.Response {
		buf.WriteString(r)
		if i < len(a.Response)-1 {
			buf.WriteString("/")
		}
	}
	return buf.String()
}
