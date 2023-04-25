package policy

import (
	"bytes"
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
	var tsaProvider TSASignatureProvider
	var envelopeProvider EnvelopeProvider
	var ok bool

	// TODO check policy in ArtifactVerificationOptions
	if tsaProvider, ok = artifact.(TSASignatureProvider); !ok {
		return nil
	}

	tsaSignatures := tsaProvider.TSASignatures()

	if certificateProvider, ok = entity.(CertificateProvider); !ok {
		return errors.New("entity does not provide a certificate")
	}

	certs, err := certProvider.CertificateChain()
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

	for i, tsaSignature := range tsaSignatures {
		tsaBytes, err := base64.StdEncoding.DecodeString(string(tsaSignature))
		if err != nil {
			return err
		}

		// TODO - Add in support for tsaverification.VerifyOpts{}
		// like Roots, maybe also Common Name?
		timestamp, err := tsaverification.VerifyTimestampResponse(tsaBytes, bytes.NewReader(dseeSignatureBytes), tsaverification.VerifyOpts{})
		if err != nil {
			return err
		}

        for _, cert := range(certs) {
            if timestamp < cert.NotBefore || timestamp > cert.NotAfter {
                return errors.New("Timestamp outside of permitted range")
            }
        }
	}
	return nil
}
