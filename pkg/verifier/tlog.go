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

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return err
	}

	entitySignature := sigContent.GetSignature()

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return err
	}

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
		if !verificationContent.CompareKey(entry.Certificate()) {
			return errors.New("transparency log certificate does not match")
		}

		// TODO: if you have access to artifact, check that it matches body subject

		// Check tlog entry time against bundle certificates
		if !verificationContent.ValidAtTime(entry.IntegratedTime()) {
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
