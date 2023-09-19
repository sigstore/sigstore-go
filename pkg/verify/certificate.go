package verify

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/github/sigstore-verifier/pkg/root"
)

func VerifyLeafCertificate(observerTimestamp time.Time, leafCert x509.Certificate, trustedMaterial root.TrustedMaterial) error { // nolint: revive
	for _, ca := range trustedMaterial.FulcioCertificateAuthorities() {
		if !ca.ValidityPeriodStart.IsZero() && leafCert.NotBefore.Before(ca.ValidityPeriodStart) {
			continue
		}
		if !ca.ValidityPeriodEnd.IsZero() && leafCert.NotAfter.After(ca.ValidityPeriodEnd) {
			continue
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

		_, err := leafCert.Verify(opts)
		if err == nil {
			return nil
		}
	}

	return errors.New("leaf certificate verification failed")
}
