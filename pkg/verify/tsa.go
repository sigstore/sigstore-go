package verify

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"

	"github.com/github/sigstore-verifier/pkg/root"
)

type TimestampAuthorityVerifier struct {
	trustedMaterial root.TrustedMaterial
	threshold       int
}

func (p *TimestampAuthorityVerifier) Verify(entity SignedEntity) ([]time.Time, error) {
	signedTimestamps, err := entity.Timestamps()

	// disallow duplicate timestamps, as a malicious actor could use duplicates to bypass the threshold
	for i := 0; i < len(signedTimestamps); i++ {
		for j := i + 1; j < len(signedTimestamps); j++ {
			if bytes.Equal(signedTimestamps[i], signedTimestamps[j]) {
				return nil, errors.New("duplicate timestamps found")
			}
		}
	}

	if err != nil || (len(signedTimestamps) < p.threshold) {
		return nil, fmt.Errorf("not enough signed timestamps: %d < %d", len(signedTimestamps), p.threshold)
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return nil, err
	}

	signatureBytes := sigContent.GetSignature()

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return nil, err
	}

	verifiedTimestamps := []time.Time{}
	for _, timestamp := range signedTimestamps {
		verifiedSignedTimestamp, err := verifySignedTimestamp(timestamp, signatureBytes, p.trustedMaterial, verificationContent)
		if err != nil {
			return nil, errors.New("unable to verify timestamp")
		}
		verifiedTimestamps = append(verifiedTimestamps, verifiedSignedTimestamp)
	}
	return verifiedTimestamps, nil
}

func verifySignedTimestamp(signedTimestamp []byte, dsseSignatureBytes []byte, trustedMaterial root.TrustedMaterial, verificationContent VerificationContent) (time.Time, error) {
	certAuthorities := trustedMaterial.TSACertificateAuthorities()

	// Iterate through TSA certificate authorities to find one that verifies
	for _, ca := range certAuthorities {
		trustedRootVerificationOptions := tsaverification.VerifyOpts{
			Roots:          []*x509.Certificate{ca.Root},
			Intermediates:  ca.Intermediates,
			TSACertificate: ca.Leaf,
		}

		// Ensure timestamp responses are from trusted sources
		timestamp, err := tsaverification.VerifyTimestampResponse(signedTimestamp, bytes.NewReader(dsseSignatureBytes), trustedRootVerificationOptions)
		if err != nil {
			continue
		}

		if !ca.ValidityPeriodStart.IsZero() && timestamp.Time.Before(ca.ValidityPeriodStart) {
			continue
		}
		if !ca.ValidityPeriodEnd.IsZero() && timestamp.Time.After(ca.ValidityPeriodEnd) {
			continue
		}

		// Check tlog entry time against bundle certificates
		// TODO: technically no longer needed since we check the cert validity period in the main Verify loop
		if !verificationContent.ValidAtTime(timestamp.Time, trustedMaterial) {
			continue
		}

		// All above verification successful, so return nil
		return timestamp.Time, nil
	}

	return time.Time{}, errors.New("Unable to verify signed timestamps")
}

func NewTimestampAuthorityVerifier(trustedMaterial root.TrustedMaterial, threshold int) *TimestampAuthorityVerifier {
	return &TimestampAuthorityVerifier{
		trustedMaterial: trustedMaterial,
		threshold:       threshold,
	}
}
