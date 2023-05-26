package policy

import (
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tlog"
)

type ArtifactTransparencyLogPolicy struct {
	trustedRoot root.TrustedRoot
	threshold   int
}

func (p *ArtifactTransparencyLogPolicy) VerifyPolicy(entity SignedEntity) error {
	entries, err := entity.TlogEntries()
	if err != nil {
		return err
	}
	if len(entries) < p.threshold {
		return fmt.Errorf("not enough transparency log entries: %d < %d", len(entries), p.threshold)
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

func NewArtifactTransparencyLogPolicy(trustedRoot root.TrustedRoot, threshold int) *ArtifactTransparencyLogPolicy {
	return &ArtifactTransparencyLogPolicy{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
