package verify

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

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

func VerifySignatureWithArtifact(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifact io.Reader) error { // nolint: revive
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

func verifyEnvelopeWithArtifact(verifier signature.Verifier, envelope EnvelopeContent, artifact io.Reader) error {
	err := verifyEnvelope(verifier, envelope)
	if err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	// Load all subject digests into a map
	subjectDigests := make(map[string][][]byte)
	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			hexdigest, err := hex.DecodeString(digest)
			if err != nil {
				return fmt.Errorf("could not verify artifact: unable to decode subject digest: %w", err)
			}
			subjectDigests[alg] = append(subjectDigests[alg], hexdigest)
		}
	}
	if len(subjectDigests) == 0 {
		return errors.New("no digests found in statement")
	}
	// Create cache of computed artifact digests, then check if any of them match the subject digests
	artifactDigests := make(map[string][]byte)
	for _, hashfunc := range []crypto.Hash{crypto.SHA512, crypto.SHA384, crypto.SHA256} {
		err = checkSubjectDigests(subjectDigests, artifactDigests, artifact, hashfunc)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("could not verify artifact: unable to confirm artifact digest is present in subject digests: %w", err)
}

func checkSubjectDigests(subjectDigests map[string][][]byte, artifactDigests map[string][]byte, artifact io.Reader, hash crypto.Hash) error {
	var alg string
	switch hash {
	case crypto.SHA512:
		alg = "sha512"
	case crypto.SHA384:
		alg = "sha384"
	case crypto.SHA256:
		alg = "sha256"
	}
	if _, ok := subjectDigests[alg]; ok {
		hasher := hash.New()
		_, err := io.Copy(hasher, artifact)
		if err != nil {
			return fmt.Errorf("could not verify artifact: unable to hash artifact: %w", err)
		}
		artifactDigests[alg] = hasher.Sum(nil)
		for _, digest := range subjectDigests[alg] {
			if bytes.Equal(artifactDigests[alg], digest) {
				return nil
			}
		}
		// None of the digests matched, so we must seek back to the start of the artifact so we can calculate the other digests
		if seeker, ok := artifact.(io.Seeker); ok {
			_, err = seeker.Seek(0, io.SeekStart)
			if err != nil {
				return fmt.Errorf("could not verify artifact: unable to seek to start of artifact: %w", err)
			}
		} else {
			return errors.New("could not verify artifact: statement contains multiple digests, so artifact must implement io.Seeker to calculate all digests")
		}
	}
	return errors.New("provided artifact digest does not match any digest in statement")
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

func verifyMessageSignature(verifier signature.Verifier, msg MessageSignatureContent, artifact io.Reader) error {
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), artifact)
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
		return errors.New("message signatures with ed25519 signatures can only be verified with artifacts, and not just their digest")
	}
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), bytes.NewReader([]byte{}), options.WithDigest(artifactDigest))

	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}
