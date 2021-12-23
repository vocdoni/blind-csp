package handlers

import (
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

	"github.com/vocdoni/blind-csp/csp"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/log"
)

const (
	ELECTION_ID_STR_LENGTH      = 64
	VOTER_ID_STR_LENGTH         = 64
	SIGNED_MESSAGE_BYTES_LENGTH = 64
)

// RsaHandler is a handler that allows only 1 registration for IP
type RsaHandler struct {
	kv        db.Database
	keysLock  sync.RWMutex
	rsaPubKey *rsa.PublicKey
}

func (rh *RsaHandler) addKey(index, value []byte) error {
	rh.keysLock.Lock()
	defer rh.keysLock.Unlock()
	tx := rh.kv.WriteTx()
	defer tx.Discard()
	if err := tx.Set(index, value); err != nil {
		return err
	}
	return tx.Commit()
}

func (rh *RsaHandler) exist(index []byte) bool {
	rh.keysLock.RLock()
	defer rh.keysLock.RUnlock()
	tx := rh.kv.WriteTx()
	defer tx.Discard()
	_, err := tx.Get(index)
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
		return fmt.Errorf("RSA Init received %d items in opts", len(opts))
	}

	rh.kv, err = metadb.New(db.TypePebble, filepath.Clean(opts[0]))
	if err != nil {
		return err
	}

	pubKeyBytes, err := os.ReadFile(opts[1])
	if err != nil {
		return err
	}

	pubK, err := parseRsaPublicKey(string(pubKeyBytes))
	if err != nil {
		return err
	}
	rh.rsaPubKey = pubK

	return err
}

// Auth is the handler for the rsa handler
func (rh *RsaHandler) Auth(r *http.Request,
	ca *csp.Message, pid []byte, st string) (bool, string) {
	log.Infof(r.UserAgent())

	authData, err := parseRsaAuthData(ca.AuthData)
	if err != nil {
		return false, err.Error()
	}

	// Verify signature
	if err := validateRsaSignature(authData.Signature, authData.Message, rh.rsaPubKey); err != nil {
		log.Warnf("invalid signature: %v", err)
		return false, "invalid signature"
	}

	if st == csp.SignatureTypeSharedKey {
		return true, "please, do not share the key"
	}
	if rh.exist(authData.VoterId) {
		log.Warnf("%s already registered", authData.VoterId)
		return false, "already registered"
	}

	err = rh.addKey(authData.VoterId, nil)
	if err != nil {
		log.Warnf("could not add key %x", authData.VoterId)
		return false, "could not add key"
	}
	log.Infof("new user registered with id %s", authData.VoterId)

	return true, ""
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

type RsaAuthData struct {
	VoterId   []byte
	Message   []byte
	Signature []byte
}

// parseRsaAuthData transforms the incoming authData string array and returns a digested output
// of the relevant parameters for the handler
func parseRsaAuthData(authData []string) (*RsaAuthData, error) {
	result := new(RsaAuthData)

	if len(authData) != 3 {
		return nil, fmt.Errorf("invalid params (3 items expected)")
	}

	// Catenate hex
	processId := authData[0]
	if len(processId) != ELECTION_ID_STR_LENGTH {
		return nil, fmt.Errorf("invalid electionId")
	}
	voterId := authData[1]
	if len(voterId) != VOTER_ID_STR_LENGTH {
		return nil, fmt.Errorf("invalid voterId")
	}

	voterIdBytes, err := hex.DecodeString(voterId)
	if err != nil || len(voterIdBytes) != VOTER_ID_STR_LENGTH/2 {
		return nil, fmt.Errorf("invalid voterId: %w", err)
	}

	message, err := hex.DecodeString(processId + voterId)
	if err != nil || len(message) != SIGNED_MESSAGE_BYTES_LENGTH {
		// By discard, only processId can be invalid
		return nil, fmt.Errorf("invalid electionId: %w", err)
	}

	signature, err := hex.DecodeString(authData[2])
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("invalid voterId")
	}

	result.VoterId = voterIdBytes
	result.Message = message
	result.Signature = signature
	return result, nil
}

// validateRsaSignature hashes the given message and verifies the signature against
// the given public key
func validateRsaSignature(signature []byte, message []byte, rsaPublicKey *rsa.PublicKey) error {
	msgHash := sha256.Sum256(message)

	return rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, msgHash[:], signature)
}
