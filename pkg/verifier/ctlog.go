package verifier

import (
	"github.com/github/sigstore-verifier/pkg/root"
)

type CertificateTransparencyLogVerifier struct {
	trustedRoot root.TrustedMaterial
	threshold   int
}

func (p *CertificateTransparencyLogVerifier) Verify(_ SignedEntity) error {
	// TODO CT verification
	return nil
}

func NewCertificateTransparencyLogVerifier(trustedRoot root.TrustedMaterial, threshold int) *CertificateTransparencyLogVerifier {
	return &CertificateTransparencyLogVerifier{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
