package handlers

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/log"
)

// SimpleMathHandler is a handler that requires a simple math operation to be resolved.
type SimpleMathHandler struct {
	kv         db.Database
	keysLock   sync.RWMutex
	mathRandom *rand.Rand
}

func (ih *SimpleMathHandler) addToken(token string, solution int) {
	ih.keysLock.Lock()
	defer ih.keysLock.Unlock()
	tx := ih.kv.WriteTx()
	defer tx.Discard()
	n := make([]byte, 32)
	binary.BigEndian.PutUint32(n, uint32(solution))
	if err := tx.Set([]byte(token), n); err != nil {
		log.Error(err)
	}
	if err := tx.Commit(); err != nil {
		log.Error(err)
	}
}

func (ih *SimpleMathHandler) getToken(token string) (int, error) {
	ih.keysLock.RLock()
	defer ih.keysLock.RUnlock()
	tx := ih.kv.WriteTx()
	defer tx.Discard()
	v, err := tx.Get([]byte(token))
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(v)), nil
}

func (ih *SimpleMathHandler) delToken(token string) {
	ih.keysLock.RLock()
	defer ih.keysLock.RUnlock()
	tx := ih.kv.WriteTx()
	defer tx.Discard()
	if err := tx.Delete([]byte(token)); err != nil {
		log.Warn(err)
	}
	if err := tx.Commit(); err != nil {
		log.Error(err)
	}
}

// GetName returns the name of the handler
func (ih *SimpleMathHandler) GetName() string {
	return "simpleMath"
}

// Init initializes the handler.
// Takes one argument for persistent data directory.
func (ih *SimpleMathHandler) Init(opts ...string) (err error) {
	ih.kv, err = metadb.New(db.TypePebble, filepath.Clean(opts[0]))
	ih.mathRandom = rand.New(rand.NewSource(time.Now().UnixNano()))
	return err
}

// Info returns the handler options and information.
func (ih *SimpleMathHandler) Info() *types.Message {
	return &types.Message{
		Title:    "Simple math challenge",
		AuthType: "blind",
		AuthSteps: []*types.AuthField{
			{Title: "Name", Type: "text"},
			{Title: "Solution", Type: "int4"},
		},
	}
}

// Redirect handler takes a client identifier and returns
func (ih *SimpleMathHandler) Redirect(clientID []byte) ([][]byte, error) {
	return nil, nil
}

// Auth is the handler method for managing the simple math authentication challenge.
func (ih *SimpleMathHandler) Auth(r *http.Request,
	c *types.Message, pid types.HexBytes, signType string, step int) AuthResponse {

	switch step {
	case 0:
		// If first step, build new challenge
		if len(c.AuthData) != 1 {
			return AuthResponse{Response: []string{"incorrect auth data fields"}}
		}
		name := c.AuthData[0]
		token := uuid.New()
		r1 := ih.mathRandom.Intn(400) + 100
		r2 := ih.mathRandom.Intn(400) + 100
		ih.addToken(token.String(), r1+r2)
		ipaddr := strings.Split(r.RemoteAddr, ":")[0]
		log.Infof("user %s from %s challenged with math question %d + %d", name, ipaddr, r1, r2)
		return AuthResponse{
			Success:   true,
			Response:  []string{fmt.Sprintf("%d", r1), fmt.Sprintf("%d", r2)},
			AuthToken: &token,
		}

	case 1:
		// If second step, check for solution
		if c.AuthToken == nil || len(c.AuthData) != 1 {
			return AuthResponse{Response: []string{"auth token not provided or missing auth data"}}
		}
		solution, err := ih.getToken(c.AuthToken.String())
		if err != nil {
			return AuthResponse{Response: []string{"auth token not found"}}
		}
		userSolution, err := strconv.Atoi(c.AuthData[0])
		if err != nil {
			return AuthResponse{Response: []string{"invalid solution format"}}
		}
		if solution != userSolution {
			return AuthResponse{Response: []string{"invalid math challenge solution"}}
		}
		ih.delToken(c.AuthToken.String())
		log.Infof("new user registered, challenge resolved %s", c.AuthData[0])
		return AuthResponse{
			Response: []string{"challenge resolved!"},
			Success:  true,
		}
	}

	return AuthResponse{Response: []string{"invalid auth step"}}
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (ih *SimpleMathHandler) RequireCertificate() bool {
	return false
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer (optional).
func (ih *SimpleMathHandler) CertificateCheck(subject []byte) bool {
	return true
}

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *SimpleMathHandler) Certificates() [][]byte {
	return nil
}
