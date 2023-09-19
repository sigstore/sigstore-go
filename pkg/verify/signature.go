package verify

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func VerifySignature(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial) error {
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelope(verifier, envelope)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		// TODO: add VerifySigWithArtifact, then error out here
		return verifyMessageSignature(verifier, msg)
	} else {
		// should never happen, but just in case:
		return fmt.Errorf("signature content has neither an envelope or a message")
	}
}

func getSignatureVerifier(verificationContent VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert, ok := verificationContent.HasCertificate(); ok {
		return signature.LoadVerifier(leafCert.PublicKey, crypto.SHA256)
	} else if pk, ok := verificationContent.HasPublicKey(); ok {
		return tm.PublicKeyVerifier(pk.Hint())
	} else {
		return nil, fmt.Errorf("no public key or certificate found")
	}
}

func verifyEnvelope(verifier signature.Verifier, envelope EnvelopeContent) error {
	pub, err := verifier.PublicKey()
	if err != nil {
		return fmt.Errorf("could not fetch verifier public key: %w", err)
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
	})

	if err != nil {
		return fmt.Errorf("could not load envelope verifier: %w", err)
	}

	_, err = envVerifier.Verify(context.TODO(), envelope.RawEnvelope())
	if err != nil {
		return fmt.Errorf("could not verify envelope: %w", err)
	}

	return nil
}

func verifyMessageSignature(verifier signature.Verifier, msg MessageSignatureContent) error {
	opts := options.WithDigest(msg.Digest())
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), bytes.NewReader([]byte{}), opts)

	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}
