package root

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"

	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"
)

type Timestamp struct {
	Time time.Time
	URI  string
}

type TimestampingAuthority interface {
	Verify(signedTimestamp []byte, signatureBytes []byte) (*Timestamp, error)
}

type SigstoreTimestampingAuthority struct {
	Root                *x509.Certificate
	Intermediates       []*x509.Certificate
	Leaf                *x509.Certificate
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
	URI                 string
}

func (tsa *SigstoreTimestampingAuthority) Verify(signedTimestamp []byte, signatureBytes []byte) (*Timestamp, error) {
	trustedRootVerificationOptions := tsaverification.VerifyOpts{
		Roots:          []*x509.Certificate{tsa.Root},
		Intermediates:  tsa.Intermediates,
		TSACertificate: tsa.Leaf,
	}

	// Ensure timestamp responses are from trusted sources
	timestamp, err := tsaverification.VerifyTimestampResponse(signedTimestamp, bytes.NewReader(signatureBytes), trustedRootVerificationOptions)
	if err != nil {
		return nil, err
	}

	if !tsa.ValidityPeriodStart.IsZero() && timestamp.Time.Before(tsa.ValidityPeriodStart) {
		return nil, errors.New("timestamp is before the validity period start")
	}
	if !tsa.ValidityPeriodEnd.IsZero() && timestamp.Time.After(tsa.ValidityPeriodEnd) {
		return nil, errors.New("timestamp is after the validity period end")
	}

	// All above verification successful, so return nil
	return &Timestamp{Time: timestamp.Time, URI: tsa.URI}, nil
}
