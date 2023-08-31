package verifier

import (
	"github.com/github/sigstore-verifier/pkg/root"
)

type CertificateTransparencyLogVerifier struct {
	trustedMaterial root.TrustedMaterial
	threshold       int
}

func (p *CertificateTransparencyLogVerifier) Verify(entity SignedEntity) error {
	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return err
	}

	return verificationContent.VerifySCT(p.threshold, p.trustedMaterial)
}

func NewCertificateTransparencyLogVerifier(trustedMaterial root.TrustedMaterial, threshold int) *CertificateTransparencyLogVerifier {
	return &CertificateTransparencyLogVerifier{
		trustedMaterial: trustedMaterial,
		threshold:       threshold,
	}
}
