package policy

import (
	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tlog"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type ArtifactTransparencyLogPolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *ArtifactTransparencyLogPolicy) VerifyPolicy(entity SignedEntity) error {
	entries, err := entity.TlogEntries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		err := tlog.ValidateEntry(entry)
		if err != nil {
			return err
		}
		err = tlog.VerifySET(entry)
		if err != nil {
			return err
		}
		// TODO: check if bundle matches entry
		// TODO: check certificate timestamps
	}

	return nil
}
