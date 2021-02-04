package handlers

import (
	"net/http"
	"strings"

	"github.com/vocdoni/blind-ca/blindca"
)

type AuthHandler interface {
	Auth(r *http.Request, ca *blindca.BlindCA) bool
}

var Handlers = map[string]AuthHandler{
	"dummy":    &DummyHandler{},
	"uniqueIp": &IpaddrHandler{},
}

func HandlersList() string {
	var h string
	for k := range Handlers {
		h += k + " "
	}
	return strings.TrimRight(h, " ")
}
