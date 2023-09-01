package verifier

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	rekorClient "github.com/sigstore/rekor/pkg/client"
	rekorGeneratedClient "github.com/sigstore/rekor/pkg/generated/client"
	rekorEntries "github.com/sigstore/rekor/pkg/generated/client/entries"
	rekorModels "github.com/sigstore/rekor/pkg/generated/models"
	rekorVerify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tlog"
)

type ArtifactTransparencyLogVerifier struct {
	trustedMaterial root.TrustedMaterial
	threshold       int
	online          bool
}

func (p *ArtifactTransparencyLogVerifier) Verify(entity SignedEntity) error {
	_, err := p.NewVerify(entity)
	return err
}

func (p *ArtifactTransparencyLogVerifier) NewVerify(entity SignedEntity) ([]time.Time, error) {
	entries, err := entity.TlogEntries()
	if err != nil {
		return nil, err
	}

	// TODO: dedupe tlog entries, since these can be maliciously repeated
	if len(entries) < p.threshold {
		return nil, fmt.Errorf("not enough transparency log entries: %d < %d", len(entries), p.threshold)
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return nil, err
	}

	entitySignature := sigContent.GetSignature()

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return nil, err
	}

	verifiedTimestamps := []time.Time{}

	for _, entry := range entries {
		err := tlog.ValidateEntry(entry)
		if err != nil {
			return nil, err
		}

		if !p.online {
			var inclusionVerified bool
			// TODO: do we validate that an entry has EITHER a promise OR a proof?
			if entry.HasInclusionPromise() {
				err = tlog.VerifySET(entry, p.trustedMaterial.TlogAuthorities())
				if err != nil {
					return nil, err
				}
				inclusionVerified = true
			}
			if entity.HasInclusionProof() {
				keyID := entry.LogKeyID()
				hex64Key := hex.EncodeToString([]byte(keyID))
				tlogVerifier, ok := p.trustedMaterial.TlogAuthorities()[hex64Key]
				if !ok {
					return nil, fmt.Errorf("unable to find tlog information for key %s", hex64Key)
				}

				verifier, err := getVerifier(tlogVerifier.PublicKey, tlogVerifier.SignatureHashFunc)
				if err != nil {
					return nil, err
				}

				err = tlog.VerifyInclusion(entry, *verifier)
				if err != nil {
					return nil, err
				}

				inclusionVerified = true
			}

			if inclusionVerified {
				verifiedTimestamps = append(verifiedTimestamps, entry.IntegratedTime())
			}
		} else {
			keyID := entry.LogKeyID()
			hex64Key := hex.EncodeToString([]byte(keyID))
			tlogVerifier, ok := p.trustedMaterial.TlogAuthorities()[hex64Key]
			if !ok {
				return nil, fmt.Errorf("unable to find tlog information for key %s", hex64Key)
			}

			client, err := getRekorClient(tlogVerifier.BaseURL)
			if err != nil {
				return nil, err
			}
			verifier, err := getVerifier(tlogVerifier.PublicKey, tlogVerifier.SignatureHashFunc)
			if err != nil {
				return nil, err
			}

			logIndex := entry.LogIndex()

			searchParams := rekorEntries.NewSearchLogQueryParams()
			searchLogQuery := rekorModels.SearchLogQuery{}
			searchLogQuery.LogIndexes = []*int64{&logIndex}
			searchParams.SetEntry(&searchLogQuery)

			resp, err := client.Entries.SearchLogQuery(searchParams)
			if err != nil {
				return nil, err
			}

			if len(resp.Payload) == 0 {
				return nil, fmt.Errorf("unable to locate log entry %d", logIndex)
			} else if len(resp.Payload) > 1 {
				return nil, errors.New("too many log entries returned")
			}

			logEntry := resp.Payload[0]

			for _, v := range logEntry {
				v := v
				err = rekorVerify.VerifyLogEntry(context.TODO(), &v, *verifier)
				if err != nil {
					return nil, err
				}
			}
			verifiedTimestamps = append(verifiedTimestamps, entry.IntegratedTime())
		}

		// Ensure entry signature matches signature from bundle
		if !bytes.Equal(entry.Signature(), entitySignature) {
			return nil, errors.New("transparency log signature does not match")
		}

		// Ensure entry certificate matches bundle certificate
		if !verificationContent.CompareKey(entry.PublicKey(), p.trustedMaterial) {
			return nil, errors.New("transparency log certificate does not match")
		}

		// TODO: if you have access to artifact, check that it matches body subject

		// Check tlog entry time against bundle certificates
		if !verificationContent.ValidAtTime(entry.IntegratedTime(), p.trustedMaterial) {
			return nil, errors.New("Integrated time outside certificate validity")
		}
	}

	return verifiedTimestamps, nil
}

func NewArtifactTransparencyLogVerifier(trustedMaterial root.TrustedMaterial, threshold int, online bool) *ArtifactTransparencyLogVerifier {
	return &ArtifactTransparencyLogVerifier{
		trustedMaterial: trustedMaterial,
		threshold:       threshold,
		online:          online,
	}
}

func getVerifier(publicKey crypto.PublicKey, hashFunc crypto.Hash) (*signature.Verifier, error) {
	verifier, err := signature.LoadVerifier(publicKey, hashFunc)
	if err != nil {
		return nil, err
	}

	return &verifier, nil
}

func getRekorClient(baseURL string) (*rekorGeneratedClient.Rekor, error) {
	client, err := rekorClient.GetRekorClient(baseURL)
	if err != nil {
		return nil, err
	}

	return client, nil
}
