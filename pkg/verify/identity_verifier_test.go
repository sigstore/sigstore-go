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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"filippo.io/mldsa"
	mldsax509 "filippo.io/mldsa/x509"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/crypto/cryptobyte"
)

func TestParseCheckpoint_MLDSA(t *testing.T) {
	// Create MLDSA keypair
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	assert.NoError(t, err)

	verifier := &mldsaLogVerifier{pubKey: privKey.Public().(*mldsa.PublicKey)}
	origin := "mock-origin"

	cp := formatsLog.Checkpoint{
		Origin: origin,
		Size:   10,
		Hash:   []byte("mock-hash"),
	}
	cpBytes := cp.Marshal()

	tstamp := time.Now().UnixNano()

	// Format msg to sign
	builder := cryptobyte.NewBuilder(nil)
	builder.AddBytes([]byte("subtree/v1\n\x00"))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(origin))
	})
	builder.AddUint64(uint64(tstamp))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(cp.Origin))
	})
	builder.AddUint64(0)
	builder.AddUint64(cp.Size)
	builder.AddBytes(cp.Hash)

	formattedMsg, err := builder.Bytes()
	assert.NoError(t, err)

	sig, err := privKey.Sign(rand.Reader, formattedMsg, nil)
	assert.NoError(t, err)

	// Prepend 8-byte timestamp
	var tBytes [8]byte
	binary.BigEndian.PutUint64(tBytes[:], uint64(tstamp))
	fullSig := append(tBytes[:], sig...)

	// Prepend 4-byte keyhash (dummy)
	fullSig = append([]byte("1234"), fullSig...)

	checkpointStr := string(cpBytes) + "\n\u2014 \n" + origin + " " + base64.StdEncoding.EncodeToString(fullSig) + "\n"

	parsedCp, timestamps, err := parseCheckpoint([]byte(checkpointStr), origin, verifier)
	assert.NoError(t, err)
	assert.NotNil(t, parsedCp)
	assert.Equal(t, origin, parsedCp.Origin)
	assert.Len(t, timestamps, 1)
	assert.Equal(t, time.Unix(0, tstamp).UnixNano(), timestamps[0].UnixNano())
}

func TestIdentityVerifier_Verify_Failure_InvalidCheckpoint(t *testing.T) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	assert.NoError(t, err)

	verifier := &mldsaLogVerifier{pubKey: privKey.Public().(*mldsa.PublicKey)}
	origin := "mock-origin"

	cp := formatsLog.Checkpoint{
		Origin: origin,
		Size:   10,
		Hash:   []byte("mock-hash"),
	}
	cpBytes := cp.Marshal()

	// Invalid signature
	checkpointStr := string(cpBytes) + "\n\u2014 \n" + origin + " " + base64.StdEncoding.EncodeToString([]byte("invalid-signature")) + "\n"

	_, _, err = parseCheckpoint([]byte(checkpointStr), origin, verifier)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify signatures on checkpoint")
}

// Mock Trusted Material
type mockIdentityTrustedMaterial struct {
	root.TrustedMaterial
	rekorLog *root.TransparencyLog
}

func (m *mockIdentityTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	if m.rekorLog == nil {
		return nil
	}
	return map[string]*root.TransparencyLog{"log": m.rekorLog}
}

type mockTCVerifier struct {
	pk crypto.PublicKey
}

func (m *mockTCVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return nil
}
func (m *mockTCVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.pk, nil
}
func (m *mockTCVerifier) ValidAtTime(_ time.Time) bool { return true }

func (m *mockIdentityTrustedMaterial) PublicKeyVerifier(_ string) (root.TimeConstrainedVerifier, error) {
	if m.rekorLog != nil {
		return &mockTCVerifier{pk: m.rekorLog.PublicKey}, nil
	}
	return nil, errors.New("not found")
}

type mockSignedEntity struct {
	BaseSignedEntity
	tlogProofs  []byte
	artifactSig []byte
	verContent  VerificationContent
}

func (m *mockSignedEntity) TlogProofs() ([]*bundleV2.TlogProof, error) {
	return []*bundleV2.TlogProof{{Proof: m.tlogProofs}}, nil
}

func (m *mockSignedEntity) SignatureContent() (SignatureContent, error) {
	return &mockSigContent{sig: m.artifactSig}, nil
}

func (m *mockSignedEntity) VerificationContent() (VerificationContent, error) {
	return m.verContent, nil
}

type mockSigContent struct {
	sig []byte
}

func (m *mockSigContent) Signature() []byte                                { return m.sig }
func (m *mockSigContent) EnvelopeContent() EnvelopeContent                 { return nil }
func (m *mockSigContent) MessageSignatureContent() MessageSignatureContent { return nil }

type mockVerContent struct {
	hint string
}

func (m *mockVerContent) CompareKey(any, root.TrustedMaterial) bool        { return true }
func (m *mockVerContent) ValidAtTime(time.Time, root.TrustedMaterial) bool { return true }
func (m *mockVerContent) Certificate() *x509.Certificate                   { return nil }
func (m *mockVerContent) Intermediates() []*x509.Certificate               { return nil }
func (m *mockVerContent) PublicKey() PublicKeyProvider {
	if m.hint == "" {
		return nil
	}
	return &mockPKProvider{hint: m.hint}
}

type mockPKProvider struct {
	hint string
}

func (m *mockPKProvider) Hint() string { return m.hint }

func TestIdentityVerifier_Verify_Success_PublicKey(t *testing.T) {
	privKey, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	origin := "mock-origin"

	// Compute expected leaf hash
	artifactDigest := sha256.Sum256([]byte("artifact"))
	msgHash := sha256.Sum256(artifactDigest[:])
	receiptDigest := sha256.Sum256([]byte("artifact-sig"))

	pubKeyBytes, _ := mldsax509.MarshalPKIXPublicKey(privKey.Public())
	rot := append([]byte("ML-DSA-44"), pubKeyBytes...)
	rootOfTrustHash := sha256.Sum256(rot)

	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, receiptDigest[:]...)

	hasher := rfc6962.DefaultHasher
	computedLeafHash := hasher.HashLeaf(leafHash)

	// Create checkpoint
	cp := formatsLog.Checkpoint{
		Origin: origin,
		Size:   1,
		Hash:   computedLeafHash,
	}
	cpBytes := cp.Marshal()

	tstamp := time.Now().UnixNano()
	builder := cryptobyte.NewBuilder(nil)
	builder.AddBytes([]byte("subtree/v1\n\x00"))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(origin))
	})
	builder.AddUint64(uint64(tstamp))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(cp.Origin))
	})
	builder.AddUint64(0)
	builder.AddUint64(cp.Size)
	builder.AddBytes(cp.Hash)
	formattedMsg, _ := builder.Bytes()

	sig, _ := privKey.Sign(rand.Reader, formattedMsg, nil)
	var tBytes [8]byte
	binary.BigEndian.PutUint64(tBytes[:], uint64(tstamp))
	fullSig := append(tBytes[:], sig...)
	fullSig = append([]byte("1234"), fullSig...) // 4-byte keyhash
	checkpointStr := string(cpBytes) + "\n\u2014 \n" + origin + " " + base64.StdEncoding.EncodeToString(fullSig) + "\n"

	tlogProof := proof.TLogProof{
		Index:      0,
		Hashes:     nil, // Since size is 1
		Checkpoint: []byte(checkpointStr),
	}
	tlogProofBytes := tlogProof.Marshal()

	entity := &mockSignedEntity{
		tlogProofs:  tlogProofBytes,
		artifactSig: []byte("artifact-sig"),
		verContent:  &mockVerContent{hint: "mock-hint"},
	}

	tm := &mockIdentityTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			PublicKey: privKey.Public(),
		},
	}

	verifier, err := NewIdentityVerifier(tm)
	assert.NoError(t, err)

	artifact := bytes.NewReader([]byte("artifact"))
	pb := NewPolicy(WithArtifact(artifact), WithoutIdentitiesUnsafe())

	res, err := verifier.Verify(entity, pb)
	assert.NoError(t, err)
	if res != nil {
		assert.True(t, res.Verified)
		assert.Len(t, res.Timestamps, 1)
	}
}

func TestIdentityVerifier_Verify_Success_OIDC(t *testing.T) {
	privKey, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	origin := "mock-origin"

	// Compute expected leaf hash
	artifactDigest := sha256.Sum256([]byte("artifact"))
	msgHash := sha256.Sum256(artifactDigest[:])
	var receiptDigest [32]byte

	rootOfTrustHash := sha256.Sum256([]byte("https://example.com"))

	hk1 := sha256.Sum256([]byte("identity"))
	hk1_2 := sha256.Sum256(hk1[:])
	hv1 := sha256.Sum256([]byte("foo@bar.com"))
	hv1_2 := sha256.Sum256(hv1[:])

	hk2 := sha256.Sum256([]byte("issuer"))
	hk2_2 := sha256.Sum256(hk2[:])
	hv2 := sha256.Sum256([]byte("https://example.com"))
	hv2_2 := sha256.Sum256(hv2[:])

	var contextHashes []byte
	contextHashes = append(contextHashes, hk1_2[:]...)
	contextHashes = append(contextHashes, hv1_2[:]...)
	contextHashes = append(contextHashes, hk2_2[:]...)
	contextHashes = append(contextHashes, hv2_2[:]...)

	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, contextHashes...)
	leafHash = append(leafHash, receiptDigest[:]...)

	hasher := rfc6962.DefaultHasher
	computedLeafHash := hasher.HashLeaf(leafHash)

	// Create checkpoint
	cp := formatsLog.Checkpoint{
		Origin: origin,
		Size:   1,
		Hash:   computedLeafHash,
	}
	cpBytes := cp.Marshal()

	tstamp := time.Now().UnixNano()
	builder := cryptobyte.NewBuilder(nil)
	builder.AddBytes([]byte("subtree/v1\n\x00"))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(origin))
	})
	builder.AddUint64(uint64(tstamp))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(cp.Origin))
	})
	builder.AddUint64(0)
	builder.AddUint64(cp.Size)
	builder.AddBytes(cp.Hash)
	formattedMsg, _ := builder.Bytes()

	sig, _ := privKey.Sign(rand.Reader, formattedMsg, nil)
	var tBytes [8]byte
	binary.BigEndian.PutUint64(tBytes[:], uint64(tstamp))
	fullSig := append(tBytes[:], sig...)
	fullSig = append([]byte("1234"), fullSig...) // 4-byte keyhash
	checkpointStr := string(cpBytes) + "\n\u2014 \n" + origin + " " + base64.StdEncoding.EncodeToString(fullSig) + "\n"

	tlogProof := proof.TLogProof{
		Index:      0,
		Hashes:     nil,
		Checkpoint: []byte(checkpointStr),
		ExtraData:  []byte("issuer:https://example.com\nidentity:foo@bar.com"),
	}
	tlogProofBytes := tlogProof.Marshal()

	entity := &mockSignedEntity{
		tlogProofs:  tlogProofBytes,
		artifactSig: nil,
		verContent:  &mockVerContent{hint: ""},
	}

	tm := &mockIdentityTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			PublicKey: privKey.Public(),
		},
	}

	verifier, err := NewIdentityVerifier(tm)
	assert.NoError(t, err)

	artifact := bytes.NewReader([]byte("artifact"))
	pb := NewPolicy(WithArtifact(artifact), WithoutIdentitiesUnsafe())

	res, err := verifier.Verify(entity, pb)
	assert.NoError(t, err)
	if res != nil {
		assert.True(t, res.Verified)
	}
}
