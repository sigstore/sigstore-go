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
		return errors.New("artifact must be provided to verify message signature")
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
		return verifyEnvelopeWithArtifact(verifier, envelope, artifact)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignature(verifier, msg, artifact)
	} else {
		// should never happen, but just in case:
		return fmt.Errorf("signature content has neither an envelope or a message")
	}
}

func VerifySignatureWithArtifactDigest(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifactDigest []byte, artifactDigestAlgorithm string) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifactDigest(verifier, envelope, artifactDigest, artifactDigestAlgorithm)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignatureWithArtifactDigest(verifier, msg, artifactDigest)
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

func verifyEnvelopeWithArtifact(verifier signature.Verifier, envelope EnvelopeContent, artifact []byte) error {
	calcDigest := sha256.Sum256(artifact) // TODO: allow other digest algorithms
	return verifyEnvelopeWithArtifactDigest(verifier, envelope, calcDigest[:], "sha256")
}

func verifyEnvelopeWithArtifactDigest(verifier signature.Verifier, envelope EnvelopeContent, artifactDigest []byte, artifactDigestAlgorithm string) error {
	err := verifyEnvelope(verifier, envelope)
	if err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			if alg == artifactDigestAlgorithm {
				if bytes.Equal([]byte(digest), artifactDigest) {
					return nil
				}
			}
		}
	}
	return errors.New("provided artifact digest does not match any digest in statement")
}

func verifyMessageSignature(verifier signature.Verifier, msg MessageSignatureContent, artifact []byte) error {
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

func verifyMessageSignatureWithArtifactDigest(verifier signature.Verifier, msg MessageSignatureContent, artifactDigest []byte) error {
	if !bytes.Equal(artifactDigest, msg.Digest()) {
		return errors.New("artifact does not match digest")
	}
	if _, ok := verifier.(*signature.ED25519Verifier); ok {
		return errors.New("unable to verify message signature with artifact digest for ed25519 signatures")
	}
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), bytes.NewReader([]byte{}), options.WithDigest(artifactDigest))

	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}
