package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vocdoni/blind-ca/blindca"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

// IDcatSubjectHex is a string that must be present on the HTTP/TLS certificate
const IDcatSubject = "CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA"

// IDcatCertificate is the IDcat ec_ciutadania default certificate
const IDcatCertificate = `
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgIQc+6uFePfrahUGpXs8lhiTzANBgkqhkiG9w0BAQsFADCB
8zELMAkGA1UEBhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2Vy
dGlmaWNhY2lvIChOSUYgUS0wODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1
YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYDVQQLEyxWZWdldSBodHRwczovL3d3
dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UECxMsSmVyYXJxdWlh
IEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMTBkVD
LUFDQzAeFw0xNDA5MTgwODIxMDBaFw0zMDA5MTgwODIxMDBaMIGGMQswCQYDVQQG
EwJFUzEzMDEGA1UECgwqQ09OU09SQ0kgQURNSU5JU1RSQUNJTyBPQkVSVEEgREUg
Q0FUQUxVTllBMSowKAYDVQQLDCFTZXJ2ZWlzIFDDumJsaWNzIGRlIENlcnRpZmlj
YWNpw7MxFjAUBgNVBAMMDUVDLUNpdXRhZGFuaWEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFkHPRZPZlXTWZ5psJhbS/Gx+bxcTpGrlVQHHtIkgGz77y
TA7UZUFb2EQMncfbOhR0OkvQQn1aMvhObFJSR6nI+caf2D+h/m/InMl1MyH3S0Ak
YGZZsthnyC6KxqK2A/NApncrOreh70ULkQs45aOKsi1kR1W0zE+iFN+/P19P7AkL
Rl3bXBCVd8w+DLhcwRrkf1FCDw6cEqaFm3cGgf5cbBDMaVYAweWTxwBZAq2RbQAW
jE7mledcYghcZa4U6bUmCBPuLOnO8KMFAvH+aRzaf3ws5/ZoOVmryyLLJVZ54peZ
OwnP9EL4OuWzmXCjBifXR2IAblxs5JYj57tls45nAgMBAAGjggHaMIIB1jASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUC2hZPofI
oxUa4ECCIl+fHbLFNxUwHwYDVR0jBBgwFoAUoMOLRKo3pUW/l4Ba0fF4opvpXY0w
gdYGA1UdIASBzjCByzCByAYEVR0gADCBvzAxBggrBgEFBQcCARYlaHR0cHM6Ly93
d3cuYW9jLmNhdC9DQVRDZXJ0L1JlZ3VsYWNpbzCBiQYIKwYBBQUHAgIwfQx7QXF1
ZXN0IGNlcnRpZmljYXQgw6lzIGVtw6hzIMO6bmljYSBpIGV4Y2x1c2l2YW1lbnQg
YSBFbnRpdGF0cyBkZSBDZXJ0aWZpY2FjacOzLiBWZWdldSBodHRwczovL3d3dy5h
b2MuY2F0L0NBVENlcnQvUmVndWxhY2lvMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2F0Y2VydC5jYXQwYgYDVR0fBFswWTBXoFWgU4Yn
aHR0cDovL2Vwc2NkLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JshihodHRwOi8v
ZXBzY2QyLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQChqFTjlAH5PyIhLjLgEs68CyNNC1+vDuZXRhy22TI83JcvGmQrZosPvVIL
PsUXx+C06Pfqmh48Q9S89X9K8w1SdJxP/rZeGEoRiKpwvQzM4ArD9QxyC8jirxex
3Umg9Ai/sXQ+1lBf6xw4HfUUr1WIp7pNHj0ZWLo106urqktcdeAFWme+/klis5fu
labCSVPuT/QpwakPrtqOhRms8vgpKiXa/eLtL9ZiA28X/Mker0zlAeTA7Z7uAnp6
oPJTlZu1Gg1ZDJueTWWsLlO+P+Wzm3MRRIbcgdRzm4mdO7ubu26SzX/aQXDhuih+
eVxXDTCfs7GUlxnjOp5j559X/N0A
-----END CERTIFICATE-----`

// IDcatHandler is a handler that checks for an idCat certificate
type IDcatHandler struct {
	// TODO: use multirpc instead of go-dvote, and replace dvote/db with
	// badger directly
	kv       *db.BadgerDB
	keysLock sync.RWMutex
}

func (ih *IDcatHandler) addKey(index, value []byte) error {
	ih.keysLock.Lock()
	defer ih.keysLock.Unlock()
	return ih.kv.Put(index, value)
}

func (ih *IDcatHandler) exist(index []byte) bool {
	ih.keysLock.RLock()
	defer ih.keysLock.RUnlock()
	_, err := ih.kv.Get(index)
	return err == nil
}

// Init initializes the IDcat handler. It takes a single argument for dataDir.
func (ih *IDcatHandler) Init(opts ...string) (err error) {
	ih.kv, err = db.NewBadgerDB(filepath.Clean(opts[0]))
	return err
}

// GetName returns the name of the handler
func (ih *IDcatHandler) GetName() string {
	return "idCat"
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (ih *IDcatHandler) RequireCertificate() bool {
	return true
}

// HardcodedCertificate returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *IDcatHandler) HardcodedCertificate() []byte {
	return []byte(IDcatCertificate)
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer.
func (ih *IDcatHandler) CertificateCheck(subject []byte) bool {
	return strings.Contains(string(subject), IDcatSubject)
}

// Auth handler checks for a valid idCat certificate and stores a hash with the
// certificate content in order to avoid future auth requests from the same identity.
func (ih *IDcatHandler) Auth(r *http.Request, ca *blindca.BlindCA) (bool, string) {
	log.Infof(r.UserAgent())
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false, "no certificate provided"
	}
	// TODO(mvdan): get rid of the redundant json steps
	// Get client certificate content
	content, err := json.MarshalIndent(r.TLS.PeerCertificates[0], "", " ")
	if err != nil {
		log.Warn(err)
		return false, "cannot get idCat certificate identity"
	}
	// Unmarshal certificate content
	ic := new(idCat)
	if err := json.Unmarshal(content, ic); err != nil {
		log.Debugf("%s", content)
		log.Warnf("json unmarshal error: %v", err)
		return false, "cannot unmarshal certificate"
	}
	// Check certificate time
	if now := time.Now(); now.After(ic.NotAfter) || now.Before(ic.NotBefore) {
		log.Warnf("certificate issued for wrong date")
		return false, "wrong date on certificate"
	}

	// Compute unique hash and check if already exist
	ichash := ic.Hash()
	if ih.exist(ichash) {
		log.Warnf("certificate %x already registered", ichash)
		return false, "certificate already used"
	}

	// Store the new certificate information
	authData := ""
	if len(ca.AuthData) > 0 {
		authData = ca.AuthData[0]
	}
	if err := ih.addKey(ichash, []byte(authData)); err != nil {
		log.Warnf("could not add key: %v", err)
		return false, "failed to add key to database"
	}

	return true, ""
}

type idCat struct {
	Issuer struct {
		Country            []string
		Organization       []string
		OrganizationalUnit []string
		Locality           string
		Province           string
		StreetAddress      string
		PostalCode         string
		SerialNumber       string
		CommonName         string
	}
	Subject struct {
		Country            []string
		Organization       []string
		OrganizationalUnit []string
		Locality           string
		Province           string
		StreetAddress      string
		PostalCode         string
		SerialNumber       string
		CommonName         string
	}
	NotBefore time.Time
	NotAfter  time.Time
}

func (ic *idCat) Hash() []byte {
	b := bytes.Buffer{}
	b.WriteString(ic.Subject.CommonName)
	b.WriteString(ic.Subject.SerialNumber)
	return ethereum.HashRaw(b.Bytes())
}
