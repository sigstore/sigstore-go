package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type CertificateTransparencyLogPolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *CertificateTransparencyLogPolicy) VerifyPolicy(_ SignedEntity) error {
	// TODO CT verification
	return nil
}
