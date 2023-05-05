package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type SigstorePolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *SigstorePolicy) VerifyPolicy(artifact any) error {
	return Verify(artifact,
		&TrustedRootPolicy{p.trustedRoot, p.opts},
	)
}

func NewSigstorePolicy() (*SigstorePolicy, error) {
	trustedRoot, err := root.GetSigstoreTrustedRoot()
	if err != nil {
		return nil, err
	}
	return &SigstorePolicy{
		trustedRoot: trustedRoot,
		opts:        root.GetDefaultOptions(),
	}, nil
}

func NewPolicy(trustedRoot *root.TrustedRoot, opts *protoverification.ArtifactVerificationOptions) *SigstorePolicy {
	return &SigstorePolicy{
		trustedRoot: trustedRoot,
		opts:        opts,
	}
}
