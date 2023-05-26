package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type TrustedRootPolicy struct {
	subPolicies []Policy
}

func (p *TrustedRootPolicy) VerifyPolicy(entity SignedEntity) error {
	return Verify(entity, p.subPolicies...)
}

func NewTrustedRootPolicy(trustedRoot *root.TrustedRoot, opts *protoverification.ArtifactVerificationOptions) *TrustedRootPolicy {
	subPolicies := []Policy{NewCertificateSignaturePolicy(trustedRoot)}

	if tsaOpts := opts.GetTsaOptions(); tsaOpts != nil {
		if !tsaOpts.GetDisable() {
			subPolicies = append(subPolicies, NewTimestampAuthorityPolicy(trustedRoot, int(tsaOpts.GetThreshold())))
		}
	}
	if tlogOptions := opts.GetTlogOptions(); tlogOptions != nil {
		if !tlogOptions.GetDisable() {
			subPolicies = append(subPolicies, NewArtifactTransparencyLogPolicy(trustedRoot, int(tlogOptions.GetThreshold())))
		}
	}
	if ctlogOptions := opts.GetCtlogOptions(); ctlogOptions != nil {
		if !ctlogOptions.GetDisable() {
			subPolicies = append(subPolicies, NewCertificateTransparencyLogPolicy(trustedRoot, int(ctlogOptions.GetThreshold())))
		}
	}

	return &TrustedRootPolicy{subPolicies}
}
