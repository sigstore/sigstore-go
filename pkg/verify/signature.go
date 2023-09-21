package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func VerifySignature(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelope(verifier, envelope)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		if _, ok := verifier.(*signature.ED25519Verifier); ok {
			return errors.New("unable to verify ED25519 signatures without providing an artifact")
		}
		return verifyMessageSignature(verifier, msg)
	} else {
		// should never happen, but just in case:
		return fmt.Errorf("signature content has neither an envelope or a message")
	}
}

func VerifySignatureWithArtifact(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifact []byte) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		// TODO: should envelope verification be supported with artifacts?
		return verifyEnvelope(verifier, envelope)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignatureWithArtifact(verifier, msg, artifact)
	} else {
		// should never happen, but just in case:
		return fmt.Errorf("signature content has neither an envelope or a message")
	}
}

func getSignatureVerifier(verificationContent VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert, ok := verificationContent.HasCertificate(); ok {
		// TODO: Inspect certificate's SignatureAlgorithm to determine hash function
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

func verifyMessageSignatureWithArtifact(verifier signature.Verifier, msg MessageSignatureContent, artifact []byte) error {
	// Ensure artifact matches digest
	switch msg.DigestAlgorithm() {
	case "SHA2_256":
		digest := sha256.Sum256(artifact)
		if !bytes.Equal(digest[:], msg.Digest()) {
			return errors.New("artifact does not match digest")
		}
	default:
		return fmt.Errorf("unsupported digest algorithm: %s", msg.DigestAlgorithm())
	}

	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), bytes.NewReader(artifact))
	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}
