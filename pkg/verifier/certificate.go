package verifier

import (
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
)

type CertificateSignatureVerifier struct {
	trustedRoot root.TrustedRoot
}

func (p *CertificateSignatureVerifier) Verify(entity SignedEntity) error {
	verificationConent, err := entity.VerificationContent()
	if err != nil {
		return err
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return err
	}

	err = verificationConent.Verify(sigContent, p.trustedRoot.FulcioCertificateAuthorities())
	return err
}

func NewCertificateSignatureVerifier(trustedRoot root.TrustedRoot) *CertificateSignatureVerifier {
	return &CertificateSignatureVerifier{
		trustedRoot: trustedRoot,
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
