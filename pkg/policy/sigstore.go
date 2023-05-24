package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type SigstorePolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *SigstorePolicy) VerifyPolicy(entity SignedEntity) error {
	return Verify(entity,
		&TrustedRootPolicy{p.trustedRoot, p.opts},
	)
}

func NewPolicy(trustedRoot *root.TrustedRoot, opts *protoverification.ArtifactVerificationOptions) *SigstorePolicy {
	return &SigstorePolicy{
		trustedRoot: trustedRoot,
		opts:        opts,
	}
}

func NewSigstorePolicy() (*SigstorePolicy, error) {
	trustedRoot, err := root.GetDefaultTrustedRoot()
	if err != nil {
		return nil, err
	}
	return NewPolicy(trustedRoot, root.GetDefaultOptions()), nil
}

func NewGitHubStagingPolicy() (*SigstorePolicy, error) {
	trustedRoot, err := root.GetGitHubStagingTrustedRoot()
	if err != nil {
		return nil, err
	}
	return NewPolicy(trustedRoot, root.GetDefaultOptions()), nil
}
