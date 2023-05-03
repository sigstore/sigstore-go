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

func (p *TimestampAuthorityPolicy) VerifyPolicy(artifact any) error {
	var signedTimestampProvider SignedTimestampProvider
	var certificateProvider CertificateProvider
	var envelopeProvider EnvelopeProvider
	var ok bool

	tsaOptions := p.opts.TsaOptions

	// TODO check policy in ArtifactVerificationOptions
	if signedTimestampProvider, ok = artifact.(SignedTimestampProvider); !ok {
		return nil
	}

	signedTimestamps, err := signedTimestampProvider.Timestamps()
	if err != nil || (len(signedTimestamps) < int(tsaOptions.Threshold) && !tsaOptions.Disable) {
		return errors.New("unable to get timestamp verification data")
	}

	if certificateProvider, ok = artifact.(CertificateProvider); !ok {
		return errors.New("entity does not provide a certificate")
	}

	certs, err := certificateProvider.CertificateChain()
	if err != nil || len(certs) == 0 {
		return errors.New("artifact does not provide a certificate")
	}

	if envelopeProvider, ok = artifact.(EnvelopeProvider); !ok {
		return nil
	}

	// TODO - bundles have one of a DSSE Envelope or a MessageSignature here; we should support the MessageSignature case in the future
	envelope, err := envelopeProvider.Envelope()
	if err != nil {
		return err
	}

	if len(envelope.Signatures) != 1 {
		return errors.New("Envelope should only have 1 signature")
	}

	dseeSignatureBytes, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return err
	}

	tsaRootCerts, tsaIntermediateCerts := p.trustedRoot.GetTSACerts()

	trustedRootVerificationOptions := tsaverification.VerifyOpts{
		Roots:         tsaRootCerts,
		Intermediates: tsaIntermediateCerts,
	}

	tsaRootCertPool := x509.NewCertPool()
	for _, rootCert := range tsaRootCerts {
		tsaRootCertPool.AddCert(rootCert)
	}

	tsaIntermediateCertPool := x509.NewCertPool()
	for _, intermediateCert := range tsaIntermediateCerts {
		tsaIntermediateCertPool.AddCert(intermediateCert)
	}

	for _, signedTimestamp := range signedTimestamps {
		// Ensure timestamp responses are from trusted sources
		timestamp, err := tsaverification.VerifyTimestampResponse(signedTimestamp, bytes.NewReader(dseeSignatureBytes), trustedRootVerificationOptions)
		if err != nil {
			return err
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

		for _, cert := range certs {
			_, err = cert.Verify(verificationOptions)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
