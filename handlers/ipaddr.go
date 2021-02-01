package handlers

import (
	"net/http"
	"strings"
	"sync"

	"github.com/vocdoni/vocdoni-blind-ca/blindca"
	"go.vocdoni.io/dvote/log"
)

// IpaddrHandler is a handler that allows only 1 registration for IP
type IpaddrHandler struct {
	kv sync.Map
}

// Auth is the handler for the ipaddr handler
func (ih *IpaddrHandler) Auth(r *http.Request, ca *blindca.BlindCA) bool {
	log.Infof(r.UserAgent())
	ipaddr := strings.Split(r.RemoteAddr, ":")[0]
	if len(ipaddr) == 0 {
		log.Warnf("cannot get ip from request: %s", r.RemoteAddr)
		return false
	}
	if _, ok := ih.kv.Load(ipaddr); ok {
		log.Warnf("ip %s already registered", ipaddr)
		return false
	}
	ih.kv.Store(ipaddr, nil)
	log.Infof("new user registered with ip %s", ipaddr)
	return true
}
