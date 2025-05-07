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
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const maxAllowedTimestamps = 32

// VerifyTimestampAuthority verifies that the given entity has been timestamped
// by a trusted timestamp authority and that the timestamp is valid.
func VerifyTimestampAuthority(entity SignedEntity, trustedMaterial root.TrustedMaterial) ([]*root.Timestamp, error) { //nolint:revive
	signedTimestamps, err := entity.Timestamps()
	if err != nil {
		return nil, err
	}

	// limit the number of timestamps to prevent DoS
	if len(signedTimestamps) > maxAllowedTimestamps {
		return nil, fmt.Errorf("too many signed timestamps: %d > %d", len(signedTimestamps), maxAllowedTimestamps)
	}

	// disallow duplicate timestamps, as a malicious actor could use duplicates to bypass the threshold
	for i := 0; i < len(signedTimestamps); i++ {
		for j := i + 1; j < len(signedTimestamps); j++ {
			if bytes.Equal(signedTimestamps[i], signedTimestamps[j]) {
				return nil, errors.New("duplicate timestamps found")
			}
		}
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return nil, err
	}

	signatureBytes := sigContent.Signature()

	verifiedTimestamps := []*root.Timestamp{}
	var errs []error
	for _, timestamp := range signedTimestamps {
		verifiedSignedTimestamp, err := verifySignedTimestamp(timestamp, signatureBytes, trustedMaterial)

		// Timestamps from unknown source are okay, but don't count as verified
		if err != nil {
			errs = append(errs, err)
			continue
		}

		verifiedTimestamps = append(verifiedTimestamps, verifiedSignedTimestamp)
	}

	// Return errors if there are any, even if there are verified timestamps.
	// This allows the caller to handle errors if the threshold is not met.
	err = nil
	if len(errs) > 0 {
		err = fmt.Errorf("verifying timestamps: %w", errors.Join(errs...))
	}
	return verifiedTimestamps, err
}

// VerifyTimestampAuthority verifies that the given entity has been timestamped
// by a trusted timestamp authority and that the timestamp is valid.
//
// The threshold parameter is the number of unique timestamps that must be
// verified.
func VerifyTimestampAuthorityWithThreshold(entity SignedEntity, trustedMaterial root.TrustedMaterial, threshold int) ([]*root.Timestamp, error) { //nolint:revive
	verifiedTimestamps, err := VerifyTimestampAuthority(entity, trustedMaterial)
	if len(verifiedTimestamps) < threshold {
		return nil, fmt.Errorf("threshold not met for verified signed timestamps: %d < %d; error: %w", len(verifiedTimestamps), threshold, err)
	}
	return verifiedTimestamps, nil
}

func verifySignedTimestamp(signedTimestamp []byte, signatureBytes []byte, trustedMaterial root.TrustedMaterial) (*root.Timestamp, error) {
	timestampAuthorities := trustedMaterial.TimestampingAuthorities()

	var errs []error

	// Iterate through TSA certificate authorities to find one that verifies
	for _, tsa := range timestampAuthorities {
		ts, err := tsa.Verify(signedTimestamp, signatureBytes)
		if err == nil {
			return ts, nil
		}
		errs = append(errs, err)
	}

	return nil, fmt.Errorf("unable to verify signed timestamps: %w", errors.Join(errs...))
}
