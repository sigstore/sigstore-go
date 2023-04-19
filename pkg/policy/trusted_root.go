package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type TrustedRootPolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *TrustedRootPolicy) VerifyPolicy(artifact any) error {
	return Verify(artifact,
		&CertificateSignaturePolicy{p.trustedRoot, p.opts},
		&ArtifactTransparencyLogPolicy{p.trustedRoot, p.opts},
		&CertificateTransparencyLogPolicy{p.trustedRoot, p.opts},
		&TimestampAuthorityPolicy{p.trustedRoot, p.opts},
	)
}
