package verifier

import (
	"github.com/github/sigstore-verifier/pkg/root"
)

type CertificateTransparencyLogVerifier struct {
	trustedRoot root.TrustedRoot
	threshold   int
}

func (p *CertificateTransparencyLogVerifier) Verify(_ SignedEntity) error {
	// TODO CT verification
	return nil
}

func NewCertificateTransparencyLogVerifier(trustedRoot root.TrustedRoot, threshold int) *CertificateTransparencyLogVerifier {
	return &CertificateTransparencyLogVerifier{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
