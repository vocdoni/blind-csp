package handlers

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vocdoni/blind-ca/blindca"
	"github.com/vocdoni/blind-ca/certvalid"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

// IDcatSubjectHex is a string that must be present on the HTTP/TLS certificate
const IDcatSubject = "CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA"

// CRLupdateInterval defines the CRL update interval
const CRLupdateInterval = time.Hour * 24

// CRLupdateDaemonCheckInterval Time to sleep between CRLupdateInternal is checked
const CRLupdateDaemonCheckInterval = time.Second * 10

// Extracts the DNI from idCat
var regexpDNI = regexp.MustCompile("[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]")

// Extracts NIE from idCat
var regexpNIE = regexp.MustCompile("[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE]")

// Extracts NIE from idCat (old)
var regexpNIEold = regexp.MustCompile("X[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]")

// Extracts Passport from idCat
var regexpPSP = regexp.MustCompile("[A-Z]{3}[0-9]{6}[A-Z]?")

var extractIDcatFunc = func(cert *x509.Certificate) string {
	if id := regexpDNI.FindString(cert.Subject.SerialNumber); len(id) > 0 {
		return id
	}
	if id := regexpNIE.FindString(cert.Subject.SerialNumber); len(id) > 0 {
		return id
	}
	if id := regexpNIEold.FindString(cert.Subject.SerialNumber); len(id) > 0 {
		return id
	}
	return regexpPSP.FindString(cert.Subject.SerialNumber)
}

type idcatCert struct {
	crtURL      string
	crlURL      string
	extractFunc func(cert *x509.Certificate) string
}

// IDcatCertificates contains the list of accepted idCat certificates
var IDcatCertificates = map[string]idcatCert{
	"ciutadania": {
		"http://www.catcert.cat/descarrega/ec-ciutadania.crt",
		"http://epscd.catcert.net/crl/ec-ciutadania.crl",
		extractIDcatFunc,
	},
	"sectorpublic": {
		"http://www.catcert.cat/descarrega/ec-sectorpublic.crt",
		"http://epscd.catcert.net/crl/ec-sectorpublic.crl",
		extractIDcatFunc,
	},
}

// IDcatHandler is a handler that checks for an idCat certificate
type IDcatHandler struct {
	ForTesting bool
	// TODO: use multirpc instead of go-dvote, and replace dvote/db with
	// badger directly
	kv            *db.BadgerDB
	keysLock      sync.RWMutex
	certManager   *certvalid.X509Manager
	crlLastUpdate time.Time
	caCerts       [][]byte
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

// Init initializes the IDcat handler. It takes one argument: dataDir
func (ih *IDcatHandler) Init(opts ...string) error {
	if len(opts) == 0 {
		return fmt.Errorf("dataDir is not specified")
	}
	var err error
	// Initialize badger DB for persistent KV storage
	ih.kv, err = db.NewBadgerDB(filepath.Clean(opts[0]))
	if err != nil {
		return err
	}
	// Create certificate manager
	ih.certManager = certvalid.NewX509Manager()
	// Add certificates to the manager
	for name, certinfo := range IDcatCertificates {
		log.Infof("fetching certificate %s", name)
		cert, err := ih.getCAcertificate(certinfo.crtURL)
		if err != nil {
			return err
		}
		xcert, err := x509.ParseCertificate(cert)
		if err != nil {
			return err
		}
		ih.certManager.Add(append([]*x509.Certificate{}, xcert), certinfo.crlURL, certinfo.extractFunc)
		ih.caCerts = append(ih.caCerts, cert)
	}
	go ih.updateCrlDaemon()
	return nil
}

// getCAcertificate obtains the CA root certificate from IDcatCAurl HTTP endpoint
func (ih *IDcatHandler) getCAcertificate(url string) ([]byte, error) {
	resp, err := http.Get(url)
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

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (ih *IDcatHandler) Certificates() [][]byte {
	return ih.caCerts
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

	// For testing purposes
	if ih.ForTesting {
		log.Debugf("certificate subject: %+v", cliCert.Subject)
	}

	// Check if cert is revokated
	certId, err := ih.certManager.Verify(cliCert, false)
	if err != nil {
		log.Warnf("invalid certificate: %v", err)
		return false, fmt.Sprintf("invalid certificate: %v", err)
	}

	// Compute the hash for saving the identifier and discard future atempts
	certIdHash := ethereum.HashRaw([]byte(certId))

	// Check if certificate ID already exist
	if ih.exist(certIdHash) && !ih.ForTesting {
		log.Warnf("certificate %x already registered", certIdHash)
		return false, "certificate already registered"
	}

	// Print cert identifier
	if ih.ForTesting {
		log.Debugf("new certificate registered: %s", certId)
	} else {
		log.Debugf("new certificate registered: %x", certIdHash)
	}

	// Store the new certificate information
	authData := ""
	for _, d := range ca.AuthData {
		authData += strings.Trim(d, ",") + ","
	}
	if err := ih.addKey(certIdHash, []byte(strings.TrimRight(authData, ","))); err != nil {
		log.Warnf("could not add key: %v", err)
		return false, "internal error 1"
	}

	return true, ""
}
