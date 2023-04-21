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
	if envelopeProvider, ok = artifact.(EnvelopeProvider); !ok {
		return nil
	}

	tsaSignatures := tsaProvider.TSASignatures()
	envelope, err := envelopeProvider.Envelope()
	if err != nil {
		return err
	}

	for i, tsaSignature := range tsaSignatures {
		tsaBytes, err := base64.StdEncoding.DecodeString(string(tsaSignature))
		if err != nil {
			return err
		}

		if i >= len(envelope.Signatures) {
			return errors.New("Unable to find matching signature for timestamp")
		}

		dseeSignatureBytes, err := base64.StdEncoding.DecodeString(envelope.Signatures[i].Sig)
		if err != nil {
			return err
		}

		// TODO - Add in support for tsaverification.VerifyOpts{}
		// like Roots, maybe also Common Name?
		timestamp, err := tsaverification.VerifyTimestampResponse(tsaBytes, bytes.NewReader(dseeSignatureBytes), tsaverification.VerifyOpts{})
		if err != nil {
			return err
		}

		// TODO - what should we check the timestamp against?
		_ = timestamp
	}
	return nil
}
