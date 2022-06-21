package handlers

import (
	"net/http"

	"github.com/vocdoni/blind-csp/types"
)

// AuthFunc is the function type required for performing an authentication
// via callback handler.
type AuthFunc = func(
	httpRequest *http.Request,
	message *types.Message,
	electionID types.HexBytes,
	signaturetype string,
	authStep int) types.AuthResponse

// InfoFunc is the function type required for providing the handler options
// and description via callback handler.
type InfoFunc = func() (message *types.Message)

// IndexerFunc is the function type used for providing the user with the list of
// processes where its participation is allowed.
type IndexerFunc = func(userID types.HexBytes) (elections []types.Election)

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
		step int) types.AuthResponse
	RequireCertificate() bool
	Certificates() [][]byte
	CertificateCheck(subject []byte) bool
	Info() *types.Message
	Indexer(userID types.HexBytes) []types.Election
}
