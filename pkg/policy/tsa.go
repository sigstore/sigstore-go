package policy

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"

	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"

	"github.com/github/sigstore-verifier/pkg/root"
)

type TimestampAuthorityPolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *TimestampAuthorityPolicy) VerifyPolicy(entity SignedEntity) error {
	tsaOptions := p.opts.TsaOptions

	if tsaOptions.Disable {
		return nil
	}

	signedTimestamps, err := entity.Timestamps()
	if err != nil || (len(signedTimestamps) < int(tsaOptions.Threshold)) {
		return errors.New("unable to get timestamp verification data")
	}

	// TODO - shouldn't we check the time in these certificates?
	certs, err := entity.CertificateChain()
	if err != nil || len(certs) == 0 {
		return errors.New("artifact does not provide a certificate")
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

	// Iterate through TSA certificate authorities to find one that verifies
	verifiedTSA := false

	for _, tsaCA := range p.trustedRoot.GetTSACertAuthorities() {
		tsaRoots := make([]*x509.Certificate, 0)
		tsaRoots = append(tsaRoots, tsaCA.Root)

		trustedRootVerificationOptions := tsaverification.VerifyOpts{
			Roots:          tsaRoots,
			Intermediates:  tsaCA.Intermediates,
			TSACertificate: tsaCA.Leaf,
		}

		tsaRootCertPool := x509.NewCertPool()
		tsaRootCertPool.AddCert(tsaCA.Root)

		tsaIntermediateCertPool := x509.NewCertPool()
		for _, intermediateCert := range tsaCA.Intermediates {
			tsaIntermediateCertPool.AddCert(intermediateCert)
		}

		for _, signedTimestamp := range signedTimestamps {
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

			_, err = tsaCA.Leaf.Verify(verificationOptions)
			if err == nil {
				verifiedTSA = true
				break
			}
		}
	}

	if !verifiedTSA {
		return errors.New("Unable to verify signed timestamps")
	}

	return nil
}
