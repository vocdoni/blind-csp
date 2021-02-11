package certvalid

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

/// Encapsulate validation of X509 certificates via a CRL
type X509CRLValidator struct {
	CA         *x509.Certificate
	list       map[string]bool
	crlURL     string
	NextUpdate time.Time
	updateLock sync.RWMutex
}

/// Create a new validator using the specified CA and the CRL url specified
func NewX509CRLValidator(ca *x509.Certificate, crlURL string) *X509CRLValidator {
	return &X509CRLValidator{
		ca, nil, crlURL, time.Now().AddDate(0, 0, -1), sync.RWMutex{},
	}
}

/// Get when the next validation call will fail because needs to call Update()
func (x *X509CRLValidator) NextUpdateLimit() time.Time {
	return x.NextUpdate
}

/// Update the CRL, is sync safe, so it can be invocated within a goroutine
func (x *X509CRLValidator) Update() error {
	resp, err := http.Get(x.crlURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("error closing HTTP body: %v\n", err)
		}
	}()

	crlBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	crl, err := x509.ParseDERCRL(crlBytes)
	if err != nil {
		return err
	}

	if err := x.CA.CheckCRLSignature(crl); err != nil {
		return err
	}

	if crl.HasExpired(time.Now()) {
		return fmt.Errorf("expired CRL")
	}

	x.NextUpdate = crl.TBSCertList.NextUpdate
	updated := make(map[string]bool, len(crl.TBSCertList.RevokedCertificates))
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		updated[revokedCert.SerialNumber.String()] = true
	}

	x.updateLock.Lock()
	x.list = updated
	x.updateLock.Unlock()
	return nil
}

func (x *X509CRLValidator) RevokatedListSize() int {
	x.updateLock.RLock()
	defer x.updateLock.RUnlock()
	return len(x.list)
}

/// IsRevokated checks if a certificate is revokated, use strict mode for production
func (x *X509CRLValidator) IsRevokated(cert *x509.Certificate, strict bool) (bool, error) {
	if strict {
		if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != x.crlURL {
			return false, fmt.Errorf("invald CRL distribution point")
		}

		if time.Now().After(x.NextUpdate) {
			return false, fmt.Errorf("CRL outdated, need to Sync()")
		}
	}
	x.updateLock.RLock()
	_, revokated := x.list[cert.SerialNumber.String()]
	x.updateLock.RUnlock()

	return revokated, nil
}
