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

var rsaPubKeys = []string{
	`-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEApc2hU8zulyJzdQE5IPAv
B2BgveoZmYUmPEjSb4DViBoATK1hlaY8Psp5vj0H0L4tM8AlXRhPQlECibhgccig
xQFcG7CLXiSAn7c4XoR+J2SCgx76Fwl9L3WhQigxyKsmpGIqubseydmwfJi4TBnq
qnX4prsW1PT8GpG35t8Qi8PtkXVGmL7G5pkPXtF0hRzKSfhzsDBbJsl6Jk/Rn5Id
pKHXL22FdbE9fGzIlW2a6Zdd0b0Q3FZBMnWLSwo0OwBtC/qNnDTCzboig9djiFmA
yuj8jVhsy050nI72TAONjGKi+xn4lYfdOV2k6TyvpRHfylHouK2v0/bktSlkFI0y
nwIBAw==
-----END PUBLIC KEY-----`,
}

// RsaHandler is a handler that allows only 1 registration for IP
type RsaHandler struct {
	kv       db.Database
	keysLock sync.RWMutex
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
	rh.kv, err = metadb.New(db.TypePebble, filepath.Clean(opts[0]))
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

	rsaPublickey, err := parseRsaPublicKey()
	if err != nil {
		return false, err.Error()
	}

	// Verify signature
	if err := validateRsaSignature(authData.Signature, authData.Message, rsaPublickey); err != nil {
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

func parseRsaPublicKey() (*rsa.PublicKey, error) {
	if len(rsaPubKeys) < 1 {
		return nil, fmt.Errorf("no public keys")
	}
	// Using the first one available so far
	block, rest := pem.Decode([]byte(rsaPubKeys[0]))
	if len(rest) > 0 {
		log.Warnf("failed to parse the public key")
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
		log.Warnf("cannot parse the public key")
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
		log.Warnf("invalid params (3 items expected)")
		return nil, fmt.Errorf("invalid params (3 items expected)")
	}

	// Catenate hex
	processId := authData[0]
	if len(processId) != ELECTION_ID_STR_LENGTH {
		log.Warnf("invalid electionId")
		return nil, fmt.Errorf("invalid electionId")
	}
	voterId := authData[1]
	if len(voterId) != VOTER_ID_STR_LENGTH {
		log.Warnf("invalid voterId")
		return nil, fmt.Errorf("invalid voterId")
	}

	voterIdBytes, err := hex.DecodeString(voterId)
	if err != nil || len(voterIdBytes) != VOTER_ID_STR_LENGTH/2 {
		log.Warnf("invalid voterId: %s", voterId)
		return nil, fmt.Errorf("invalid voterId: %w", err)
	}

	message, err := hex.DecodeString(processId + voterId)
	if err != nil || len(message) != SIGNED_MESSAGE_BYTES_LENGTH {
		// By discard, only processId can be invalid
		log.Warnf("invalid electionId: %s", processId)
		return nil, fmt.Errorf("invalid electionId: %w", err)
	}

	signature, err := hex.DecodeString(authData[2])
	if err != nil || len(signature) == 0 {
		log.Warnf("invalid signature: %s", signature)
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
