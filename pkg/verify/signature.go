package verify

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func VerifySignature(sigContent bundle.SignatureContent, verificationContent bundle.VerificationContent, trustedMaterial root.TrustedMaterial) error {
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope, ok := sigContent.HasEnvelope(); ok {
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

		_, err = envVerifier.Verify(context.TODO(), envelope.Envelope)
		if err != nil {
			return fmt.Errorf("failed to verify envelope: %w", err)
		}

		return nil
	} else if msg, ok := sigContent.HasMessage(); ok {
		// TODO: add VerifySigWithArtifact, then error out here
		opts := options.WithDigest(msg.Digest)
		err = verifier.VerifySignature(bytes.NewReader(msg.GetSignature()), bytes.NewReader([]byte{}), opts)

		if err != nil {
			return fmt.Errorf("failed to verify message: %w", err)
		}

		return nil
	} else {
		// should never happen, but just in case:
		return fmt.Errorf("signature content has neither an envelope or a message")
	}
}

func getSignatureVerifier(verificationContent bundle.VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert, ok := verificationContent.HasCertificate(); ok {
		return signature.LoadVerifier(leafCert.PublicKey, crypto.SHA256)
	} else if pk, ok := verificationContent.HasPublicKey(); ok {
		return tm.PublicKeyVerifier(pk.Hint)
	} else {
		return nil, fmt.Errorf("no public key or certificate found")
	}
}

type SignatureVerifier struct {
	trustedMaterial root.TrustedMaterial
}

// TODO: Do we need this? only called in tests
func (p *SignatureVerifier) Verify(entity SignedEntity) error {
	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return err
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return err
	}

	err = verificationContent.Verify(sigContent, p.trustedMaterial)
	return err
}

func NewSignatureVerifier(trustedMaterial root.TrustedMaterial) *SignatureVerifier {
	return &SignatureVerifier{
		trustedMaterial: trustedMaterial,
	}
}

type CertificateOIDCVerifier struct {
	expectedOIDC string
}

func (p *CertificateOIDCVerifier) Verify(entity SignedEntity) error {
	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return err
	}

	issuer := verificationContent.GetIssuer()
	if issuer != p.expectedOIDC {
		return fmt.Errorf("Signing certificate Issuer OID %s does not match expected OIDC issuer %s", issuer, p.expectedOIDC)
	}

	return nil
}

func NewCertificateOIDCVerifier(expectedOIDC string) *CertificateOIDCVerifier {
	return &CertificateOIDCVerifier{
		expectedOIDC: expectedOIDC,
	}
}

type CertificateSANVerifier struct {
	expectedSAN string
}

func (p *CertificateSANVerifier) Verify(entity SignedEntity) error {
	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return err
	}

	san := verificationContent.GetSAN()
	if san != p.expectedSAN {
		return fmt.Errorf("Signing certificate subject %s does not match expected subject %s", san, p.expectedSAN)
	}

	return nil
}

func NewCertificateSANVerifier(expectedSAN string) *CertificateSANVerifier {
	return &CertificateSANVerifier{
		expectedSAN: expectedSAN,
	}
}
