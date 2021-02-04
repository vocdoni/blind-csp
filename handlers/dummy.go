package handlers

import (
	"net/http"
	"strings"

	"github.com/vocdoni/blind-ca/blindca"
	"go.vocdoni.io/dvote/log"
)

// DummyHandler is a handler for testing that returns always true
type DummyHandler struct {
}

// Auth is the handler for the dummy handler
func (dh *DummyHandler) Auth(r *http.Request, ca *blindca.BlindCA) bool {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	if len(ipaddr) == 0 {
		log.Warnf("cannot get ip from request: %s", r.RemoteAddr)
		return false
	}
	log.Infof("new user registered with ip %s", ipaddr)
	return true
}
