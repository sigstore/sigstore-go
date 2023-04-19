package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type TimestampAuthorityPolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *TimestampAuthorityPolicy) VerifyPolicy(artifact any) error {
	var tsaProvider TSASignatureProvider
	var ok bool
	// TODO check policy in ArtifactVerificationOptions
	if tsaProvider, ok = artifact.(TSASignatureProvider); !ok {
		return nil
	}
	tsaSignatures := tsaProvider.TSASignatures()
	_ = tsaSignatures // TODO verify with TSA
	return nil
}
