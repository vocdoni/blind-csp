package handlerlist

import (
	"sort"
	"strings"

	"github.com/vocdoni/blind-csp/handlers"
	"github.com/vocdoni/blind-csp/handlers/idcathandler"
	"github.com/vocdoni/blind-csp/handlers/rsahandler"
	"github.com/vocdoni/blind-csp/handlers/smshandler"
)

// Handlers contains the list of available handlers
var Handlers = map[string]handlers.AuthHandler{
	"dummy":        &handlers.DummyHandler{},
	"uniqueIp":     &handlers.IpaddrHandler{},
	"simpleMath":   &handlers.SimpleMathHandler{},
	"idCat":        &idcathandler.IDcatHandler{ForTesting: false},
	"idCatTesting": &idcathandler.IDcatHandler{ForTesting: true},
	"rsa":          &rsahandler.RsaHandler{},
	"sms":          &smshandler.SmsHandler{},
}

// HandlersList returns a human friendly string with the list of available handlers.
func HandlersList() string {
	var hl []string
	for k := range Handlers {
		hl = append(hl, k)
	}
	sort.Strings(hl)
	return strings.Join(hl, ",")
}
