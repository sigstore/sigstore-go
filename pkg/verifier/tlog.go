package verifier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tlog"
)

type ArtifactTransparencyLogVerifier struct {
	trustedRoot root.TrustedRoot
	threshold   int
}

func (p *ArtifactTransparencyLogVerifier) Verify(entity SignedEntity) error {
	entries, err := entity.TlogEntries()
	if err != nil {
		return err
	}
	if len(entries) < p.threshold {
		return fmt.Errorf("not enough transparency log entries: %d < %d", len(entries), p.threshold)
	}

	content, err := entity.Content()
	if err != nil {
		return err
	}

	entitySignature := content.GetSignature()

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

		// Ensure entry signature matches signature from bundle
		if !bytes.Equal(entry.Signature(), entitySignature) {
			return errors.New("transparency log signature does not match")
		}

		// Ensure entry certificate matches bundle certificate
		if !leafCert.Equal(entry.Certificate()) {
			return errors.New("transparency log certificate does not match")
		}

		// TODO: if you have access to artifact, check that it matches body subject

		// Check tlog entry time against bundle certificates
		if leafCert.NotBefore.After(entry.IntegratedTime()) || leafCert.NotAfter.Before(entry.IntegratedTime()) {
			return errors.New("Integrated time outside certificate validity")
		}
	}

	return nil
}

func NewArtifactTransparencyLogVerifier(trustedRoot root.TrustedRoot, threshold int) *ArtifactTransparencyLogVerifier {
	return &ArtifactTransparencyLogVerifier{
		trustedRoot: trustedRoot,
		threshold:   threshold,
	}
}
