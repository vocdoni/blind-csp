package handlers

import (
	"bytes"
	"net/http"

	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/types"
)

// AuthFunc is the function type required for performing an authentication
// via callback handler.
type AuthFunc = func(*http.Request, *types.Message, types.HexBytes, string, int) AuthResponse

// InfoFunc is the function type required for providing the handler options
// and description via callback handler
type InfoFunc = func() *types.Message

// AuthHandler is the interface that all CSP handlers should implement.
// The Auth method must return either the request is valid or not.
// The current signatureType supported are:
//  1. ecdsa: performs a plain ECDSA signature over the payload provided by the user
//  2. blind: performs a blind ECDSA signature over the payload provided by the user
//  3. sharedkey: performs a plain ECDSA signature over hash(processId)
type AuthHandler interface {
	Init(opts ...string) error
	GetName() string
	Auth(r *http.Request, msg *types.Message, processID types.HexBytes,
		signatureType string, step int) AuthResponse
	RequireCertificate() bool
	Certificates() [][]byte
	CertificateCheck(subject []byte) bool
	Info() *types.Message
}

// AuthResponse is the type returned by Auth methods on the AuthHandler interface.
// If success true and AuthToken is nil, authentication process is considered finished,
// and the CSP signature is provided to the user.
type AuthResponse struct {
	Success   bool
	Response  []string
	AuthToken *uuid.UUID
}

func (a *AuthResponse) String() string {
	if len(a.Response) == 0 {
		return ""
	}
	var buf bytes.Buffer
	for i, r := range a.Response {
		buf.WriteString(r)
		if i < len(a.Response)-1 {
			buf.WriteString("/")
		}
	}
	return buf.String()
}
