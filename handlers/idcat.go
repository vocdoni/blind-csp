package handlers

import (
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vocdoni/blind-ca/blindca"
	"github.com/vocdoni/blind-ca/certvalid"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

// IDcatSubjectHex is a string that must be present on the HTTP/TLS certificate
const IDcatSubject = "CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA"

// IDcatCAurl defines where to find the CA root certificate
const IDcatCAurl = "http://www.catcert.cat/descarrega/ec-ciutadania.crt"

// IDcatCRL is the HTTP endpoint for CRL fetching
const IDcatCRL = "http://epscd.catcert.net/crl/ec-ciutadania.crl"

// CRLupdateInterval defines the CRL update interval
const CRLupdateInterval = time.Hour * 24

// CRLupdateDaemonCheckInterval Time to sleep between CRLupdateInternal is checked
const CRLupdateDaemonCheckInterval = time.Second * 10

var regexpDNI = regexp.MustCompile("[0-9]{8}[A-Z]")

var extractIDcatFunc = func(cert *x509.Certificate) string {
	return regexpDNI.FindString(cert.Subject.SerialNumber)
}

// IDcatHandler is a handler that checks for an idCat certificate
type IDcatHandler struct {
	// TODO: use multirpc instead of go-dvote, and replace dvote/db with
	// badger directly
	kv            *db.BadgerDB
	keysLock      sync.RWMutex
	certManager   *certvalid.X509Manager
	crlLastUpdate time.Time
	caCert        []byte
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
	// Initialize badger DB for persistent KV storage
	ih.kv, err = db.NewBadgerDB(filepath.Clean(opts[0]))
	if err != nil {
		return err
	}
	// Create the CRL validator (for revokated certificates)
	cert, err := x509.ParseCertificate(ih.Certificate())
	if err != nil {
		return err
	}

	ih.certManager = certvalid.NewX509Manager()
	ih.certManager.Add(append([]*x509.Certificate{}, cert), IDcatCRL, extractIDcatFunc)
	go ih.updateCrlDaemon()
	return nil
}

// getCAcertificate obtains the CA root certificate from IDcatCAurl HTTP endpoint
func (ih *IDcatHandler) getCAcertificate() ([]byte, error) {
	if ih.caCert != nil {
		return ih.caCert, nil
	}
	resp, err := http.Get(IDcatCAurl)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			panic("error closing HTTP body request on getCAcertificate")
		}
	}()
	return ioutil.ReadAll(resp.Body)
}

// updateCrlDaemon is a blocking routine that updates the CRL list
func (ih *IDcatHandler) updateCrlDaemon() {
	for {
		if now := time.Now(); now.After(ih.crlLastUpdate.Add(CRLupdateInterval)) {
			log.Infof("updating CRL lists")
			// Give time to the daemon to update (60 extra seconds) before considering
			// CRL list not updated (if strict mode).
			if err := ih.certManager.Update(
				now.Add(CRLupdateInterval).Add(60 * time.Second)); err != nil {
				log.Errorf("updateCrlDaemon: %v", err)
			} else {
				// Only update crlLastUpdate if 100% success, else it will try again on new iteration
				ih.crlLastUpdate = now.Add(CRLupdateInterval)
			}
			log.Infof("got %d revoked certificates from CRL", ih.certManager.RevokedListsSize())
		}
		time.Sleep(CRLupdateDaemonCheckInterval)
	}
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

// Certificate returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *IDcatHandler) Certificate() []byte {
	cert, err := ih.getCAcertificate()
	if err != nil {
		panic(err)
	}
	return cert
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer.
func (ih *IDcatHandler) CertificateCheck(subject []byte) bool {
	return strings.Contains(string(subject), IDcatSubject)
}

// Auth handler checks for a valid idCat certificate and stores a hash with the
// certificate content in order to avoid future auth requests from the same identity.
func (ih *IDcatHandler) Auth(r *http.Request, ca *blindca.BlindCA) (bool, string) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false, "no certificate provided"
	}

	// Get the client certificate and check that it is actually from the required issues
	cliCert := r.TLS.PeerCertificates[0]
	if !strings.Contains(cliCert.Issuer.String(), IDcatSubject) {
		log.Warnf("client certificate is not issued by %s but %s", IDcatSubject, cliCert.Issuer.String())
		return false, "client certificate is not issued by the required CA"
	}

	// Check certificate time
	if now := time.Now(); now.After(cliCert.NotAfter) || now.Before(cliCert.NotBefore) {
		log.Warnf("certificate issued for wrong date")
		return false, "wrong date on certificate"
	}

	// Check if cert is revokated
	certId, err := ih.certManager.Verify(cliCert, false)
	if err != nil {
		log.Warnf("revoked certificate")
		return false, "revoked certificate"
	}

	// Compute unique identifier and check if already exist
	if ih.exist([]byte(certId)) {
		log.Warnf("certificate %x already registered", certId)
		return false, "certificate already used"
	}

	// TODO check if we can use the following fields
	// cliCert.Subject.CommonName => Name + Surnames
	// cliCert.Subject.SerialNumber => DNI + (sometimes Name)

	// Store the new certificate information
	authData := ""
	if len(ca.AuthData) > 0 {
		authData = ca.AuthData[0]
	}
	if err := ih.addKey([]byte(certId), []byte(authData)); err != nil {
		log.Warnf("could not add key: %v", err)
		return false, "internal error 1"
	}

	return true, ""
}
