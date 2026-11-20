// Copyright 2026 The Sigstore Authors.
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
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"time"

	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	rekorVerify "github.com/sigstore/rekor-tiles/v2/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	merkleproof "github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	contextClaimKey    = "context"
	maxExtraDataClaims = 64
	maxExtraDataBytes  = 64 * 1024
)

// verifyIdentityCheckpoint verifies a transparency log checkpoint against the
// trusted material's Rekor logs and returns the parsed checkpoint and any
// verified timestamps embedded in checkpoint signatures.
func verifyIdentityCheckpoint(tlogProof *proof.TLogProof, trustedMaterial root.TrustedMaterial) (*formatsLog.Checkpoint, []time.Time, error) {
	if len(tlogProof.Checkpoint) == 0 {
		return nil, nil, errors.New("invalid checkpoint format")
	}

	var verifyErrors []error
	for _, rekorLog := range trustedMaterial.RekorLogs() {
		if rekorLog == nil {
			continue
		}
		if rekorLog.BaseURL == "" {
			verifyErrors = append(verifyErrors, errors.New("cannot verify checkpoint without baseUrl in transparency log"))
			continue
		}
		u, err := url.Parse(rekorLog.BaseURL)
		if err != nil {
			verifyErrors = append(verifyErrors, err)
			continue
		}
		if u.Hostname() == "" {
			verifyErrors = append(verifyErrors, errors.New("cannot verify checkpoint without valid host in transparency log baseUrl"))
			continue
		}

		verifier, err := signature.LoadVerifier(rekorLog.PublicKey, crypto.Hash(0))
		if err != nil {
			verifyErrors = append(verifyErrors, fmt.Errorf("LoadVerifier failed: %w", err))
			continue
		}

		parsedCheckpoint, timestamps, err := parseCheckpoint(tlogProof.Checkpoint, u.Hostname(), verifier)
		if err != nil {
			verifyErrors = append(verifyErrors, fmt.Errorf("parseCheckpoint failed: %w", err))
			continue
		}

		validAtAll := true
		for _, ts := range timestamps {
			if (!rekorLog.ValidityPeriodStart.IsZero() && ts.Before(rekorLog.ValidityPeriodStart)) ||
				(!rekorLog.ValidityPeriodEnd.IsZero() && ts.After(rekorLog.ValidityPeriodEnd)) {
				validAtAll = false
				break
			}
		}
		if !validAtAll {
			verifyErrors = append(verifyErrors, errors.New("checkpoint timestamp outside transparency log validity period"))
			continue
		}

		return parsedCheckpoint, timestamps, nil
	}

	return nil, nil, fmt.Errorf("failed to verify checkpoint against any trusted log. Errors: %v", verifyErrors)
}

func parseCheckpoint(chkpt []byte, origin string, verifier signature.Verifier) (*formatsLog.Checkpoint, []time.Time, error) {
	pk, err := verifier.PublicKey()
	if err != nil {
		return nil, nil, err
	}
	mldsaKey, isMLDSA := pk.(*mldsa.PublicKey)
	if !isMLDSA || mldsaKey.Parameters() != mldsa.MLDSA44() {
		return nil, nil, errors.New("checkpoint public key must be an ML-DSA-44 key")
	}

	noteVerifier, err := note.NewNoteVerifier(origin, verifier)
	if err != nil {
		return nil, nil, fmt.Errorf("loading note verifier: %w", err)
	}
	cp, parsedNote, err := rekorVerify.VerifyWitnessedCheckpoint(string(chkpt), noteVerifier)
	if err != nil {
		return nil, nil, err
	}

	// ML-DSA checkpoints use the cosignature/v1 (subtree/v1) note format that
	// embeds an 8-byte Unix timestamp immediately after the 4-byte key hash.
	var verifiedTimestamps []time.Time
	for _, sig := range parsedNote.Sigs {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding checkpoint signature: %w", err)
		}
		if len(sigBytes) < 12 {
			return nil, nil, errors.New("checkpoint signature too short to contain timestamp")
		}
		t := binary.BigEndian.Uint64(sigBytes[4:12])
		if t > math.MaxInt64 {
			return nil, nil, errors.New("checkpoint timestamp overflows int64")
		}
		verifiedTimestamps = append(verifiedTimestamps, time.Unix(int64(t), 0))
	}
	if len(verifiedTimestamps) == 0 {
		return nil, nil, errors.New("no verified timestamps found in ML-DSA checkpoint")
	}

	return cp, verifiedTimestamps, nil
}

// parseExtraData parses newline-separated key:value claims from the tlog proof's extra data.
func parseExtraData(extraData []byte) (map[string]string, error) {
	if len(extraData) == 0 {
		return nil, nil
	}
	if len(extraData) > maxExtraDataBytes {
		return nil, fmt.Errorf("tlog extra data exceeds maximum size of %d bytes", maxExtraDataBytes)
	}
	extraClaims := make(map[string]string)
	lines := bytes.SplitSeq(extraData, []byte("\n"))
	for line := range lines {
		if len(line) == 0 {
			continue
		}
		if len(extraClaims) >= maxExtraDataClaims {
			return nil, fmt.Errorf("too many claims in tlog extra data: max %d", maxExtraDataClaims)
		}
		lineParts := bytes.SplitN(line, []byte(":"), 2)
		if len(lineParts) != 2 {
			return nil, errors.New("malformed claim in tlog extra data")
		}
		key := string(lineParts[0])
		if key == "" {
			return nil, errors.New("empty claim key in tlog extra data")
		}
		if _, exists := extraClaims[key]; exists {
			return nil, fmt.Errorf("duplicate claim %q in tlog extra data", key)
		}
		extraClaims[key] = string(lineParts[1])
	}
	return extraClaims, nil
}

// computeContextClaimHashes validates and computes the context claim bytes and
// double-hashed context claim pair for a public-key credential if the "context"
// claim is present in extraClaims.
func computeContextClaimHashes(extraClaims map[string]string) ([]byte, []byte, error) {
	for k := range extraClaims {
		if k != contextClaimKey {
			return nil, nil, fmt.Errorf("unexpected claim %q in tlog extra data for public key credential", k)
		}
	}
	contextVal, ok := extraClaims[contextClaimKey]
	if !ok || len(contextVal) == 0 {
		return nil, nil, nil
	}
	if len(contextVal) != sha256.Size*2 {
		return nil, nil, fmt.Errorf("context must be a %d-byte SHA-256 digest (%d hex chars), got %d hex chars", sha256.Size, sha256.Size*2, len(contextVal))
	}
	contextBytes, err := hex.DecodeString(contextVal)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode hex context value: %w", err)
	}
	k1 := sha256.Sum256([]byte(contextClaimKey))
	kDoubleHash := sha256.Sum256(k1[:])
	vDoubleHash := sha256.Sum256(contextBytes)
	var contextHashes []byte
	contextHashes = append(contextHashes, kDoubleHash[:]...)
	contextHashes = append(contextHashes, vDoubleHash[:]...)
	return contextBytes, contextHashes, nil
}

// computeOIDCClaimHashes double-hashes and lexicographically sorts all extraClaims
// by their double-hashed key for an OIDC credential leaf.
func computeOIDCClaimHashes(extraClaims map[string]string) []byte {
	if len(extraClaims) == 0 {
		return nil
	}
	type kv struct {
		hk [sha256.Size]byte
		hv [sha256.Size]byte
	}
	kvs := make([]kv, 0, len(extraClaims))
	for k, val := range extraClaims {
		hk := sha256.Sum256([]byte(k))
		hv := sha256.Sum256([]byte(val))
		kvs = append(kvs, kv{
			hk: sha256.Sum256(hk[:]),
			hv: sha256.Sum256(hv[:]),
		})
	}
	sort.Slice(kvs, func(i, j int) bool {
		return bytes.Compare(kvs[i].hk[:], kvs[j].hk[:]) < 0
	})
	var contextHashes []byte
	for _, pair := range kvs {
		contextHashes = append(contextHashes, pair.hk[:]...)
		contextHashes = append(contextHashes, pair.hv[:]...)
	}
	return contextHashes
}

// verifyIdentityInclusionProof reconstructs the identity transparency leaf hash
// and verifies the RFC 6962 Merkle inclusion proof against the checkpoint.
func verifyIdentityInclusionProof(tlogProof *proof.TLogProof, cp *formatsLog.Checkpoint, rootOfTrustHash [32]byte, msgHash [32]byte, contextHashes []byte, receiptDigest [32]byte) error {
	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, contextHashes...)
	leafHash = append(leafHash, receiptDigest[:]...)

	hasher := rfc6962.DefaultHasher
	computedLeafHash := hasher.HashLeaf(leafHash)

	proofHashes := make([][]byte, len(tlogProof.Hashes))
	for i, h := range tlogProof.Hashes {
		proofHashes[i] = h[:]
	}

	if err := merkleproof.VerifyInclusion(hasher, tlogProof.Index, cp.Size, computedLeafHash, proofHashes, cp.Hash); err != nil {
		return fmt.Errorf("failed to verify inclusion proof: %w", err)
	}
	return nil
}
