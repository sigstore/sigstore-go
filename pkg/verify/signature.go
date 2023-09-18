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

	if envelope, ok := sigContent.HasEnvelope(); ok {
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

		_, err = envVerifier.Verify(context.TODO(), envelope.GetRawEnvelope())
		if err != nil {
			return fmt.Errorf("could not verify envelope: %w", err)
		}
	} else if msg, ok := sigContent.HasMessage(); ok {
		// TODO: add VerifySigWithArtifact, then error out here
		opts := options.WithDigest(msg.GetDigest())
		err = verifier.VerifySignature(bytes.NewReader(msg.GetSignature()), bytes.NewReader([]byte{}), opts)

		if err != nil {
			return fmt.Errorf("could not verify message: %w", err)
		}
	} else {
		// should never happen, but just in case:
		return fmt.Errorf("signature content has neither an envelope or a message")
	}

	return nil
}

func getSignatureVerifier(verificationContent VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert, ok := verificationContent.HasCertificate(); ok {
		return signature.LoadVerifier(leafCert.PublicKey, crypto.SHA256)
	} else if pk, ok := verificationContent.HasPublicKey(); ok {
		return tm.PublicKeyVerifier(pk.GetHint())
	} else {
		return nil, fmt.Errorf("no public key or certificate found")
	}
}
