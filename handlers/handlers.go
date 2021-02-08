package handlers

import (
	"net/http"
	"strings"

	"github.com/vocdoni/blind-ca/blindca"
)

type AuthHandler interface {
	Init(opts ...string) error
	GetName() string
	Auth(r *http.Request, ca *blindca.BlindCA) (bool, string)
	RequireCertificate() bool
	HardcodedCertificate() []byte
	CertificateCheck(subject []byte) bool
}

var Handlers = map[string]AuthHandler{
	"dummy":    &DummyHandler{},
	"uniqueIp": &IpaddrHandler{},
	"idCat":    &IDcatHandler{},
}

func HandlersList() string {
	var h string
	for k := range Handlers {
		h += k + " "
	}
	return strings.TrimRight(h, " ")
}
