package handlerlist

import (
	"strings"

	"github.com/vocdoni/blind-csp/handlers"
	"github.com/vocdoni/blind-csp/handlers/idcathandler"
	"github.com/vocdoni/blind-csp/handlers/rsahandler"
)

// Handlers contains the list of available handlers
var Handlers = map[string]handlers.AuthHandler{
	"dummy":        &handlers.DummyHandler{},
	"uniqueIp":     &handlers.IpaddrHandler{},
	"simpleMath":   &handlers.SimpleMathHandler{},
	"idCat":        &idcathandler.IDcatHandler{ForTesting: false},
	"idCatTesting": &idcathandler.IDcatHandler{ForTesting: true},
	"rsa":          &rsahandler.RsaHandler{},
}

// HandlersList returns a human friendly string with the list of available handlers.
func HandlersList() string {
	var h string
	for k := range Handlers {
		h += k + " "
	}
	return strings.TrimRight(h, " ")
}
