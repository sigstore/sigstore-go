package policy

import (
	"errors"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tlog"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type ArtifactTransparencyLogPolicy struct {
	trustedRoot *root.TrustedRoot
	opts        *protoverification.ArtifactVerificationOptions
}

func (p *ArtifactTransparencyLogPolicy) VerifyPolicy(entity any) error {
	var tlogProvider TlogEntryProvider
	var ok bool
	if tlogProvider, ok = entity.(TlogEntryProvider); !ok {
		return errors.New("entity is not a TLogProvider")
	}
	entries, err := tlogProvider.TlogEntries()
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
