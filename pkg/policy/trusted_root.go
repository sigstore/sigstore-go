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

func GetDefaultOptions() *protoverification.ArtifactVerificationOptions {
	return &protoverification.ArtifactVerificationOptions{
		Signers: nil,
		TlogOptions: &protoverification.ArtifactVerificationOptions_TlogOptions{
			Threshold:                 1,
			PerformOnlineVerification: false,
			Disable:                   false,
		},
		CtlogOptions: &protoverification.ArtifactVerificationOptions_CtlogOptions{
			Threshold:   1,
			DetachedSct: false,
			Disable:     false,
		},
		TsaOptions: &protoverification.ArtifactVerificationOptions_TimestampAuthorityOptions{
			Threshold: 1,
			Disable:   true,
		},
	}
}

func NewTrustedRootPolicy(trustedRoot root.TrustedRoot, opts *protoverification.ArtifactVerificationOptions) *TrustedRootPolicy {
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
