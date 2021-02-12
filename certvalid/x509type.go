package certvalid

import (
	"crypto/x509"
	"fmt"
	"time"
)

type ExtractIDFunc func(*x509.Certificate) string

type X509Type struct {
	verifyOptions x509.VerifyOptions
	crlValidator  *X509CRLValidator
	extractID     ExtractIDFunc
}

type X509Manager struct {
	types []X509Type
}

func NewX509Manager() *X509Manager {
	return &X509Manager{[]X509Type{}}
}

func (x *X509Manager) Add(chain []*x509.Certificate, crlURL string, extratIdFunc ExtractIDFunc) {
	rootPool := x509.NewCertPool()
	rootPool.AddCert(chain[0])

	subPool := x509.NewCertPool()
	for _, sub := range chain[1:] {
		subPool.AddCert(sub)
	}

	crlValidator := NewX509CRLValidator(chain[len(chain)-1], crlURL)
	verifyOptions := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: subPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	x.types = append(x.types,
		X509Type{
			verifyOptions,
			crlValidator,
			extratIdFunc,
		},
	)
}

func (x *X509Manager) Update(nextUpdate time.Time) error {
	errm := ""
	for _, v := range x.types {
		if err := v.crlValidator.Update(); err != nil {
			errm += fmt.Sprintf("%s ", v.crlValidator.crlURL)
			continue // do not block CRL updates for other certificates
		}
		v.crlValidator.NextUpdate = nextUpdate
	}
	if errm != "" {
		return fmt.Errorf("some CRL updates failed: %s", errm)
	}
	return nil
}

func (x *X509Manager) RevokedListsSize() int {
	size := 0
	for _, v := range x.types {
		size += v.crlValidator.RevokatedListSize()
	}
	return size
}

func (x *X509Manager) Verify(cert *x509.Certificate, strict bool) (string, error) {
	for _, v := range x.types {
		if _, err := cert.Verify(v.verifyOptions); err == nil {
			isRevokated, err := v.crlValidator.IsRevokated(cert, strict)
			if err != nil {
				return "", err
			}
			if isRevokated {
				return "", fmt.Errorf("certificate is revokated")
			}
			cid := v.extractID(cert)
			if len(cid) == 0 {
				return "", fmt.Errorf("certificate ID invalid")
			}
			return cid, nil
		}
	}
	return "", fmt.Errorf("cannot find suitable CA")
}
