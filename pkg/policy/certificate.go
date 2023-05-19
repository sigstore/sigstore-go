package policy

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

type CertificateSignaturePolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *CertificateSignaturePolicy) VerifyPolicy(entity SignedEntity) error {
	certs, err := entity.CertificateChain()
	if err != nil || len(certs) == 0 {
		return errors.New("artifact does not provide a certificate")
	}
	verifier, err := signature.LoadVerifier(certs[0].PublicKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	envelope, err := entity.Envelope()
	if err != nil {
		return errors.New("artifact does not provide an envelope")
	}
	err = verifyEnvelope(envelope, verifier)
	if err != nil {
		return fmt.Errorf("envelope verification failed: %w", err)
	}

	return nil
}

func verifyEnvelope(envelope *dsse.Envelope, verifier signature.Verifier) error {
	pub, err := verifier.PublicKey()
	if err != nil {
		return err
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
	})
	if err != nil {
		return err
	}
	_, err = envVerifier.Verify(context.TODO(), envelope)
	if err != nil {
		return err
	}
	return nil
}
