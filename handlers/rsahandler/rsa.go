package rsahandler

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/vocdoni/blind-csp/handlers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/log"
)

const (
	electionIDStrLength      = 64
	voterIDStrLength         = 64
	signedMessageBytesLength = 64
)

// RsaHandler is a handler that allows only 1 registration for IP
type RsaHandler struct {
	kv        db.Database
	keysLock  sync.RWMutex
	rsaPubKey *rsa.PublicKey
}

func (rh *RsaHandler) addKey(voterID, processID []byte) error {
	rh.keysLock.Lock()
	defer rh.keysLock.Unlock()
	tx := rh.kv.WriteTx()
	defer tx.Discard()
	var key bytes.Buffer
	_, err := key.Write(processID)
	if err != nil {
		return err
	}
	_, err = key.Write(voterID)
	if err != nil {
		return err
	}
	if err := tx.Set(key.Bytes(), nil); err != nil {
		return err
	}
	return tx.Commit()
}

func (rh *RsaHandler) exist(voterID, processID []byte) bool {
	rh.keysLock.RLock()
	defer rh.keysLock.RUnlock()
	tx := rh.kv.ReadTx()
	defer tx.Discard()
	var key bytes.Buffer
	_, err := key.Write(processID)
	if err != nil {
		return false
	}
	_, err = key.Write(voterID)
	if err != nil {
		return false
	}
	_, err = tx.Get(key.Bytes())
	return err == nil
}

// GetName returns the name of the handler
func (rh *RsaHandler) GetName() string {
	return "rsa"
}

// Init initializes the handler.
// Takes one argument for persistent data directory.
func (rh *RsaHandler) Init(opts ...string) (err error) {
	if len(opts) != 2 {
		return fmt.Errorf("rsa handler requires a file path with the validation RSA key")
	}

	rh.kv, err = metadb.New(db.TypePebble, filepath.Clean(opts[0]))
	if err != nil {
		return err
	}

	pubKeyBytes, err := os.ReadFile(opts[1])
	if err != nil {
		return err
	}

	rh.rsaPubKey, err = parseRsaPublicKey(string(pubKeyBytes))
	return err
}

// Info returns the handler options and required auth steps.
// TODO: needs to be adapted!
func (rh *RsaHandler) Info() *types.Message {
	return &types.Message{
		Title:    "RSA signature",
		AuthType: "blind",
		AuthSteps: []*types.AuthField{
			{Title: "Election ID", Type: "hex32"},
			{Title: "Voter ID", Type: "hex32"},
			{Title: "Signature", Type: "text"},
		},
	}
}

// Auth is the handler for the rsa handler
func (rh *RsaHandler) Auth(r *http.Request,
	ca *types.Message, pid types.HexBytes, st string, step int) handlers.AuthResponse {
	authData, err := parseRsaAuthData(ca.AuthData)
	if err != nil {
		log.Warn(err)
		return handlers.AuthResponse{}
	}
	if !bytes.Equal(pid, authData.ProcessId) {
		return handlers.AuthResponse{Response: []string{"the provided electionId does not match the URL one"}}
	}

	// Verify signature
	if err := validateRsaSignature(authData.Signature, authData.Message, rh.rsaPubKey); err != nil {
		return handlers.AuthResponse{Response: []string{"invalid signature"}}
	}

	if st == types.SignatureTypeSharedKey {
		return handlers.AuthResponse{Response: []string{"please, do not share the key"}}
	}

	if rh.exist(authData.VoterId, authData.ProcessId) {
		return handlers.AuthResponse{Response: []string{"already registered"}}
	}

	err = rh.addKey(authData.VoterId, authData.ProcessId)
	if err != nil {
		return handlers.AuthResponse{Response: []string{"could not add key"}}
	}
	log.Infof("new user registered with id %x", authData.VoterId)

	return handlers.AuthResponse{Success: true}
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (rh *RsaHandler) RequireCertificate() bool {
	return false
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer (optional).
func (rh *RsaHandler) CertificateCheck(subject []byte) bool {
	return true
}

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (rh *RsaHandler) Certificates() [][]byte {
	return nil
}

// Internal data handlers

func parseRsaPublicKey(pubKey string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(pubKey))
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to parse the public key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch parsedKey.(type) {
	case *rsa.PublicKey:
		break
	default:
		return nil, fmt.Errorf("cannot parse the public key")
	}
	return parsedKey.(*rsa.PublicKey), nil
}

type rsaAuthData struct {
	ProcessId []byte
	VoterId   []byte
	Message   []byte
	Signature []byte
}

// parseRsaAuthData transforms the incoming authData string array and returns a digested output
// of the relevant parameters for the handler
func parseRsaAuthData(authData []string) (*rsaAuthData, error) {
	if len(authData) != 3 {
		return nil, fmt.Errorf("invalid params (3 items expected)")
	}

	// Catenate hex
	processId := authData[0]
	if len(authData[0]) != electionIDStrLength {
		return nil, fmt.Errorf("invalid electionId")
	}
	processIdBytes, err := hex.DecodeString(authData[0])
	if err != nil {
		return nil, fmt.Errorf("cannot decode processId")
	}
	voterId := authData[1]
	if len(voterId) != voterIDStrLength {
		return nil, fmt.Errorf("invalid voterId")
	}
	voterIdBytes, err := hex.DecodeString(voterId)
	if err != nil || len(voterIdBytes) != voterIDStrLength/2 {
		return nil, fmt.Errorf("invalid voterId format: %w", err)
	}
	message, err := hex.DecodeString(processId + voterId)
	if err != nil || len(message) != signedMessageBytesLength {
		// By discard, only processId can be invalid
		return nil, fmt.Errorf("invalid electionId: %w", err)
	}
	signature, err := hex.DecodeString(authData[2])
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("invalid signature format")
	}

	return &rsaAuthData{
		ProcessId: processIdBytes,
		VoterId:   voterIdBytes,
		Message:   message,
		Signature: signature,
	}, nil
}

// validateRsaSignature hashes the given message and verifies the signature against
// the given public key
func validateRsaSignature(signature []byte, message []byte, rsaPublicKey *rsa.PublicKey) error {
	msgHash := sha256.Sum256(message)

	return rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, msgHash[:], signature)
}
