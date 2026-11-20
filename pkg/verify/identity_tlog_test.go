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
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
)

type mockTlogTrustedMaterial struct {
	root.BaseTrustedMaterial
	rekorLog  *root.TransparencyLog
	rekorLogs map[string]*root.TransparencyLog
}

func (m *mockTlogTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	if m.rekorLogs != nil {
		return m.rekorLogs
	}
	if m.rekorLog == nil {
		return nil
	}
	return map[string]*root.TransparencyLog{"log": m.rekorLog}
}

func buildSignedCheckpoint(t *testing.T, privKey crypto.PrivateKey, origin string, size uint64, hash []byte) []byte {
	t.Helper()
	cp := formatsLog.Checkpoint{
		Origin: origin,
		Size:   size,
		Hash:   hash,
	}

	signer, err := signature.LoadDefaultSigner(privKey)
	require.NoError(t, err)

	noteSigner, err := note.NewNoteSigner(context.Background(), origin, signer)
	require.NoError(t, err)

	signedNote, err := sumdbNote.Sign(&sumdbNote.Note{Text: string(cp.Marshal())}, noteSigner)
	require.NoError(t, err)
	return signedNote
}

func TestParseCheckpoint_MLDSA(t *testing.T) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	verifier, err := signature.LoadVerifier(privKey.Public(), 0)
	require.NoError(t, err)
	origin := "mock-origin"

	rootHash := sha256.Sum256([]byte("mock-hash"))
	checkpointBytes := buildSignedCheckpoint(t, privKey, origin, 10, rootHash[:])

	parsedCp, timestamps, err := parseCheckpoint(checkpointBytes, origin, verifier)
	require.NoError(t, err)
	require.NotNil(t, parsedCp)
	assert.Equal(t, origin, parsedCp.Origin)
	require.Len(t, timestamps, 1)
	assert.False(t, timestamps[0].IsZero())
}

func TestParseCheckpoint_Ed25519_Rejected(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier, err := signature.LoadVerifier(pubKey, 0)
	require.NoError(t, err)
	origin := "mock-origin"

	rootHash := sha256.Sum256([]byte("mock-hash"))
	checkpointBytes := buildSignedCheckpoint(t, privKey, origin, 10, rootHash[:])

	_, _, err = parseCheckpoint(checkpointBytes, origin, verifier)
	assert.ErrorContains(t, err, "checkpoint public key must be an ML-DSA-44 key")
}

func TestParseCheckpoint_InvalidSignature(t *testing.T) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	verifier, err := signature.LoadVerifier(privKey.Public(), 0)
	require.NoError(t, err)
	origin := "mock-origin"

	rootHash := sha256.Sum256([]byte("mock-hash"))
	cp := formatsLog.Checkpoint{
		Origin: origin,
		Size:   10,
		Hash:   rootHash[:],
	}
	cpBytes := cp.Marshal()

	checkpointStr := string(cpBytes) + "\n\u2014 " + origin + " " + base64.StdEncoding.EncodeToString([]byte("invalid-signature")) + "\n"

	_, _, err = parseCheckpoint([]byte(checkpointStr), origin, verifier)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unverified checkpoint signature")
}

func TestVerifyIdentityCheckpoint_And_InclusionProof(t *testing.T) {
	origin := "mock-origin"

	rootOfTrustHash := sha256.Sum256([]byte("https://example.com"))
	artifactDigest := sha256.Sum256([]byte("artifact"))
	msgHash := sha256.Sum256(artifactDigest[:])
	var receiptDigest [32]byte

	extraData := []byte("issuer:https://example.com\nidentity:foo@bar.com")
	extraClaims, err := parseExtraData(extraData)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", extraClaims["issuer"])
	assert.Equal(t, "foo@bar.com", extraClaims["identity"])

	contextHashes := computeOIDCClaimHashes(extraClaims)
	require.Len(t, contextHashes, 4*sha256.Size)

	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, contextHashes...)
	leafHash = append(leafHash, receiptDigest[:]...)
	computedLeafHash := rfc6962.DefaultHasher.HashLeaf(leafHash)

	t.Run("ML-DSA-44", func(t *testing.T) {
		privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)

		checkpointBytes := buildSignedCheckpoint(t, privKey, origin, 1, computedLeafHash)
		tlogProof := &proof.TLogProof{
			Index:      0,
			Hashes:     nil,
			Checkpoint: checkpointBytes,
			ExtraData:  extraData,
		}
		tm := &mockTlogTrustedMaterial{
			rekorLog: &root.TransparencyLog{
				BaseURL:   "https://" + origin,
				PublicKey: privKey.Public(),
			},
		}

		cp, timestamps, err := verifyIdentityCheckpoint(tlogProof, tm)
		require.NoError(t, err)
		require.NotNil(t, cp)
		require.Len(t, timestamps, 1)

		err = verifyIdentityInclusionProof(tlogProof, cp, rootOfTrustHash, msgHash, contextHashes, receiptDigest)
		require.NoError(t, err)

		// Tampered message hash should fail inclusion proof
		badMsgHash := sha256.Sum256([]byte("tampered"))
		err = verifyIdentityInclusionProof(tlogProof, cp, rootOfTrustHash, badMsgHash, contextHashes, receiptDigest)
		assert.ErrorContains(t, err, "failed to verify inclusion proof")

		// Empty checkpoint should fail
		_, _, err = verifyIdentityCheckpoint(&proof.TLogProof{}, tm)
		assert.ErrorContains(t, err, "invalid checkpoint format")

		// Missing BaseURL should fail
		_, _, err = verifyIdentityCheckpoint(tlogProof, &mockTlogTrustedMaterial{
			rekorLog: &root.TransparencyLog{
				PublicKey: privKey.Public(),
			},
		})
		assert.ErrorContains(t, err, "cannot verify checkpoint without baseUrl in transparency log")

		// Mismatched BaseURL origin should fail
		_, _, err = verifyIdentityCheckpoint(tlogProof, &mockTlogTrustedMaterial{
			rekorLog: &root.TransparencyLog{
				BaseURL:   "https://wrong-origin",
				PublicKey: privKey.Public(),
			},
		})
		assert.ErrorContains(t, err, "failed to verify checkpoint against any trusted log")

		// Expired log key (ValidityPeriodEnd before checkpoint timestamp) should fail
		_, _, err = verifyIdentityCheckpoint(tlogProof, &mockTlogTrustedMaterial{
			rekorLog: &root.TransparencyLog{
				BaseURL:             "https://" + origin,
				PublicKey:           privKey.Public(),
				ValidityPeriodStart: time.Now().Add(-2 * time.Hour),
				ValidityPeriodEnd:   time.Now().Add(-time.Hour),
			},
		})
		assert.ErrorContains(t, err, "checkpoint timestamp outside transparency log validity period")

		// Multiple logs in trusted material
		otherKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
		require.NoError(t, err)
		cp, timestamps, err = verifyIdentityCheckpoint(tlogProof, &mockTlogTrustedMaterial{
			rekorLogs: map[string]*root.TransparencyLog{
				"older": {
					BaseURL:             "https://" + origin,
					PublicKey:           otherKey.Public(),
					ValidityPeriodStart: time.Now().Add(-2 * time.Hour),
				},
				"newer": {
					BaseURL:             "https://" + origin,
					PublicKey:           privKey.Public(),
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, cp)
		require.Len(t, timestamps, 1)

		// Empty RekorLogs should fail checkpoint verification
		_, _, err = verifyIdentityCheckpoint(tlogProof, &mockTlogTrustedMaterial{})
		assert.ErrorContains(t, err, "failed to verify checkpoint against any trusted log")
	})

	t.Run("Ed25519 rejected", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		checkpointBytes := buildSignedCheckpoint(t, privKey, origin, 1, computedLeafHash)
		tlogProof := &proof.TLogProof{
			Index:      0,
			Hashes:     nil,
			Checkpoint: checkpointBytes,
			ExtraData:  extraData,
		}
		tm := &mockTlogTrustedMaterial{
			rekorLog: &root.TransparencyLog{
				BaseURL:   "https://" + origin,
				PublicKey: pubKey,
			},
		}

		_, _, err = verifyIdentityCheckpoint(tlogProof, tm)
		assert.ErrorContains(t, err, "checkpoint public key must be an ML-DSA-44 key")
	})
}

func TestParseExtraData_And_ContextClaims(t *testing.T) {
	claims, err := parseExtraData(nil)
	require.NoError(t, err)
	assert.Nil(t, claims)

	_, err = parseExtraData([]byte("malformed-claim-without-colon"))
	assert.ErrorContains(t, err, "malformed claim in tlog extra data")

	_, err = parseExtraData([]byte(":empty-key"))
	assert.ErrorContains(t, err, "empty claim key in tlog extra data")

	_, err = parseExtraData(make([]byte, maxExtraDataBytes+1))
	assert.ErrorContains(t, err, "tlog extra data exceeds maximum size")

	_, err = parseExtraData([]byte("identity:a@b.com\nidentity:c@d.com"))
	assert.ErrorContains(t, err, "duplicate claim \"identity\" in tlog extra data")

	contextDigest := sha256.Sum256([]byte("build-context"))
	claims, err = parseExtraData([]byte("context:" + hex.EncodeToString(contextDigest[:])))
	require.NoError(t, err)

	gotCtx, contextHashes, err := computeContextClaimHashes(claims)
	require.NoError(t, err)
	assert.Equal(t, contextDigest[:], gotCtx)
	assert.Len(t, contextHashes, 2*sha256.Size)

	invalidHex64 := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	_, _, err = computeContextClaimHashes(map[string]string{"context": invalidHex64})
	assert.ErrorContains(t, err, "failed to decode hex context value")

	_, _, err = computeContextClaimHashes(map[string]string{"context": hex.EncodeToString([]byte("short"))})
	assert.ErrorContains(t, err, "context must be a 32-byte SHA-256 digest")

	_, _, err = computeContextClaimHashes(map[string]string{"issuer": "https://example.com"})
	assert.ErrorContains(t, err, "unexpected claim \"issuer\" in tlog extra data for public key credential")
}
