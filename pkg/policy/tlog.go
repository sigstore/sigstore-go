package policy

import (
	"errors"
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

	certs, err := entity.CertificateChain()
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("missing certificate chain")
	}

	leafCert := certs[0]

	for _, entry := range entries {
		err := tlog.ValidateEntry(entry)
		if err != nil {
			return err
		}
		err = tlog.VerifySET(entry, p.trustedRoot.TlogVerifiers())
		if err != nil {
			return err
		}

		// TODO: check if bundle matches entry

		// Check tlog entry time against bundle certificates
		if leafCert.NotBefore.After(entry.IntegratedTime()) || leafCert.NotAfter.Before(entry.IntegratedTime()) {
			return errors.New("Integrated time outside certificate validity")
		}
	}

	return nil
}

func NewArtifactTransparencyLogPolicy(trustedRoot root.TrustedRoot, threshold int) *ArtifactTransparencyLogPolicy {
	return &ArtifactTransparencyLogPolicy{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
