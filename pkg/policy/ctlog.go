package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
)

type CertificateTransparencyLogPolicy struct {
	trustedRoot *root.TrustedRoot
	threshold   int
}

func (p *CertificateTransparencyLogPolicy) VerifyPolicy(_ SignedEntity) error {
	// TODO CT verification
	return nil
}

func NewCertificateTransparencyLogPolicy(trustedRoot *root.TrustedRoot, threshold int) *CertificateTransparencyLogPolicy {
	return &CertificateTransparencyLogPolicy{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
