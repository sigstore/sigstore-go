// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

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

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
)

// VerifyArtifactTransparencyLog verifies that the given entity has been logged
// in the transparency log and that the log entry is valid.
//
// The threshold parameter is the number of unique transparency log entries
// that must be verified.
//
// If online is true, the log entry is verified against the Rekor server.
func VerifyArtifactTransparencyLog(entity SignedEntity, trustedMaterial root.TrustedMaterial, threshold int, online bool) ([]time.Time, error) { //nolint:revive
	entries, err := entity.TlogEntries()
	if err != nil {
		return nil, err
	}

	// disallow duplicate entries, as a malicious actor could use duplicates to bypass the threshold
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].LogKeyID() == entries[j].LogKeyID() && entries[i].LogIndex() == entries[j].LogIndex() {
				return nil, errors.New("duplicate tlog entries found")
			}
		}
	}
	if len(entries) < threshold {
		return nil, fmt.Errorf("not enough transparency log entries: %d < %d", len(entries), threshold)
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return nil, err
	}

	entitySignature := sigContent.Signature()

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

		if !online {
			var inclusionVerified bool
			// TODO: do we validate that an entry has EITHER a promise OR a proof?
			if entry.HasInclusionPromise() {
				err = tlog.VerifySET(entry, trustedMaterial.TlogAuthorities())
				if err != nil {
					return nil, err
				}
				inclusionVerified = true
			}
			if entity.HasInclusionProof() {
				keyID := entry.LogKeyID()
				hex64Key := hex.EncodeToString([]byte(keyID))
				tlogVerifier, ok := trustedMaterial.TlogAuthorities()[hex64Key]
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
			tlogVerifier, ok := trustedMaterial.TlogAuthorities()[hex64Key]
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
		if !verificationContent.CompareKey(entry.PublicKey(), trustedMaterial) {
			return nil, errors.New("transparency log certificate does not match")
		}

		// TODO: if you have access to artifact, check that it matches body subject

		// Check tlog entry time against bundle certificates
		if !verificationContent.ValidAtTime(entry.IntegratedTime(), trustedMaterial) {
			return nil, errors.New("integrated time outside certificate validity")
		}
	}

	return verifiedTimestamps, nil
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
