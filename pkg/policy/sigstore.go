package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
)

func NewSigstorePublicPolicy() (*TrustedRootPolicy, error) {
	trustedRoot, err := root.GetDefaultTrustedRoot()
	if err != nil {
		return nil, err
	}
	return NewTrustedRootPolicy(trustedRoot, root.GetDefaultOptions()), nil
}

// NewGitHubPolicy returns a policy that verifies signatures using the GitHub
// staging root. This is temporary until we distribute the root via TUF.
func NewGitHubStagingPolicy() (*TrustedRootPolicy, error) {
	trustedRoot, err := root.GetGitHubStagingTrustedRoot()
	if err != nil {
		return nil, err
	}
	return NewTrustedRootPolicy(trustedRoot, root.GetDefaultOptions()), nil
}
