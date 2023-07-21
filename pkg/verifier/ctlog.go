package verifier

import (
	"github.com/github/sigstore-verifier/pkg/root"
)

type CertificateTransparencyLogVerifier struct {
	trustedMaterial root.TrustedMaterial
	threshold       int
}

func (p *CertificateTransparencyLogVerifier) Verify(_ SignedEntity) error {
	// TODO CT verification
	return nil
}

func NewCertificateTransparencyLogVerifier(trustedMaterial root.TrustedMaterial, threshold int) *CertificateTransparencyLogVerifier {
	return &CertificateTransparencyLogVerifier{
		trustedMaterial: trustedMaterial,
		threshold:       threshold,
	}
}
