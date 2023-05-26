package policy

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"

	"github.com/github/sigstore-verifier/pkg/root"
)

type TimestampAuthorityPolicy struct {
	trustedRoot root.TrustedRoot
	threshold   int
}

func (p *TimestampAuthorityPolicy) VerifyPolicy(entity SignedEntity) error {
	signedTimestamps, err := entity.Timestamps()
	if err != nil || (len(signedTimestamps) < p.threshold) {
		return fmt.Errorf("not enough signed timestamps: %d < %d", len(signedTimestamps), p.threshold)
	}

	// TODO - bundles have one of a DSSE Envelope or a MessageSignature here; we should support the MessageSignature case in the future
	envelope, err := entity.Envelope()
	if err != nil {
		return err
	}

	if len(envelope.Signatures) != 1 {
		return errors.New("Envelope should only have 1 signature")
	}

	dsseSignatureBytes, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return err
	}

	certAuthorities := p.trustedRoot.TSACertificateAuthorities()

	for _, timestamp := range signedTimestamps {
		err = verifySignedTimestamp(timestamp, dsseSignatureBytes, certAuthorities)
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

func NewTimestampAuthorityPolicy(trustedRoot root.TrustedRoot, threshold int) *TimestampAuthorityPolicy {
	return &TimestampAuthorityPolicy{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
