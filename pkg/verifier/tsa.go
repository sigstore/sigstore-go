package verifier

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"

	"github.com/github/sigstore-verifier/pkg/root"
)

type TimestampAuthorityVerifier struct {
	trustedRoot root.TrustedMaterial
	threshold   int
}

func (p *TimestampAuthorityVerifier) Verify(entity SignedEntity) error {
	signedTimestamps, err := entity.Timestamps()
	if err != nil || (len(signedTimestamps) < p.threshold) {
		return fmt.Errorf("not enough signed timestamps: %d < %d", len(signedTimestamps), p.threshold)
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return err
	}

	signatureBytes := sigContent.GetSignature()

	certAuthorities := p.trustedRoot.TSACertificateAuthorities()

	for _, timestamp := range signedTimestamps {
		err = verifySignedTimestamp(timestamp, signatureBytes, certAuthorities)
		if err != nil {
			return errors.New("unable to verify timestamp")
		}
	}
	return nil
}

func verifySignedTimestamp(signedTimestamp []byte, dsseSignatureBytes []byte, certAuthorities []root.CertificateAuthority) error {
	// Iterate through TSA certificate authorities to find one that verifies
	for _, ca := range certAuthorities {
		trustedRootVerificationOptions := tsaverification.VerifyOpts{
			Roots:          []*x509.Certificate{ca.Root},
			Intermediates:  ca.Intermediates,
			TSACertificate: ca.Leaf,
		}

		tsaRootCertPool := x509.NewCertPool()
		tsaRootCertPool.AddCert(ca.Root)

		tsaIntermediateCertPool := x509.NewCertPool()
		for _, intermediateCert := range ca.Intermediates {
			tsaIntermediateCertPool.AddCert(intermediateCert)
		}

		// Ensure timestamp responses are from trusted sources
		timestamp, err := tsaverification.VerifyTimestampResponse(signedTimestamp, bytes.NewReader(dsseSignatureBytes), trustedRootVerificationOptions)
		if err != nil {
			continue
		}

		// Check that the timestamp is valid for the provided certificate
		verificationOptions := x509.VerifyOptions{
			CurrentTime:   timestamp.Time,
			Roots:         tsaRootCertPool,
			Intermediates: tsaIntermediateCertPool,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageTimeStamping,
			},
		}

		_, err = ca.Leaf.Verify(verificationOptions)
		if err != nil {
			continue
		}
		if !ca.ValidityPeriodStart.IsZero() && timestamp.Time.Before(ca.ValidityPeriodStart) {
			continue
		}
		if !ca.ValidityPeriodEnd.IsZero() && timestamp.Time.After(ca.ValidityPeriodEnd) {
			continue
		}

		// All above verification successful, so return nil
		return nil
	}

	return errors.New("Unable to verify signed timestamps")
}

func NewTimestampAuthorityVerifier(trustedRoot root.TrustedMaterial, threshold int) *TimestampAuthorityVerifier {
	return &TimestampAuthorityVerifier{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
