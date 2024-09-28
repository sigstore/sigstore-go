package root

import (
	"crypto/x509"
	"errors"
	"time"
)

type CertificateAuthority interface {
	Verify(cert *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error)
}

type FulcioCertificateAuthority struct {
	Root                *x509.Certificate
	Intermediates       []*x509.Certificate
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
	URI                 string
}

func (ca *FulcioCertificateAuthority) Verify(cert *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error) {
	if !ca.ValidityPeriodStart.IsZero() && observerTimestamp.Before(ca.ValidityPeriodStart) {
		return nil, errors.New("certificate is not valid yet")
	}
	if !ca.ValidityPeriodEnd.IsZero() && observerTimestamp.After(ca.ValidityPeriodEnd) {
		return nil, errors.New("certificate is no longer valid")
	}

	rootCertPool := x509.NewCertPool()
	rootCertPool.AddCert(ca.Root)
	intermediateCertPool := x509.NewCertPool()
	for _, cert := range ca.Intermediates {
		intermediateCertPool.AddCert(cert)
	}

	// From spec:
	// > ## Certificate
	// > For a signature with a given certificate to be considered valid, it must have a timestamp while every certificate in the chain up to the root is valid (the so-called “hybrid model” of certificate verification per Braun et al. (2013)).

	opts := x509.VerifyOptions{
		CurrentTime:   observerTimestamp,
		Roots:         rootCertPool,
		Intermediates: intermediateCertPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	}

	return cert.Verify(opts)
}
