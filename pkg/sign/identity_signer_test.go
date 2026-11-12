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

package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	verifyBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
)

type mockTlog struct {
	calls int
	err   error
}

func (m *mockTlog) GetIdentityTransparencyLogEntry(_ context.Context, _ *pbrekor.IdentityRequestV001) (*bundleV2.TransparencyLogProof, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return &bundleV2.TransparencyLogProof{
		Proof: []byte("mock-proof"),
	}, nil
}

func TestIdentityBundle(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}

	keypair, err := NewMLDSAKeypair()
	require.NoError(t, err)

	cred := &PublicKeyCredential{
		Keypair: keypair,
	}

	tlog := &mockTlog{}
	opts := IdentityBundleOptions{
		Context:         context.Background(),
		TransparencyLog: tlog,
	}

	b, err := IdentityBundle(content, cred, opts)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, 1, tlog.calls)
	assert.Equal(t, "application/vnd.dev.sigstore.bundle.v2.0+json", b.MediaType)
	require.NotNil(t, b.VerificationMaterial.GetTransparencyLogProof())
	assert.Equal(t, []byte("mock-proof"), b.VerificationMaterial.GetTransparencyLogProof().Proof)
	assert.NotEmpty(t, b.VerificationMaterial.GetTransparencyLogProof().GetSignature().GetSignature())
	assert.Nil(t, b.GetPayload())

	bv2, err := verifyBundle.NewBundleV2(b)
	require.NoError(t, err)
	assert.False(t, bv2.HasEnvelope())
	assert.True(t, bv2.HasTransparencyLogProof())
}

func TestIdentityBundle_DSSEData(t *testing.T) {
	content := &DSSEData{
		Data:        []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
		PayloadType: "application/vnd.in-toto+json",
	}

	keypair, err := NewMLDSAKeypair()
	require.NoError(t, err)

	cred := &PublicKeyCredential{Keypair: keypair}
	opts := IdentityBundleOptions{
		Context:         context.Background(),
		TransparencyLog: &mockTlog{},
	}

	b, err := IdentityBundle(content, cred, opts)
	require.NoError(t, err)
	require.NotNil(t, b)
	require.NotNil(t, b.GetPayload())
	assert.Equal(t, content.Data, b.GetPayload().Payload)
	assert.Equal(t, content.PayloadType, b.GetPayload().PayloadType)
	assert.NotEmpty(t, b.VerificationMaterial.GetTransparencyLogProof().GetSignature().GetSignature())

	bv2, err := verifyBundle.NewBundleV2(b)
	require.NoError(t, err)
	assert.True(t, bv2.HasEnvelope())

	tlog := &mockTlog{}
	_, err = IdentityBundle(&DSSEData{}, cred, IdentityBundleOptions{TransparencyLog: tlog})
	assert.ErrorContains(t, err, "DSSEData must have non-empty data and payload type")
	assert.Equal(t, 0, tlog.calls)
}

func TestIdentityBundle_NoTlog(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	cred := &OIDCCredential{Token: "fake-token"}
	opts := IdentityBundleOptions{Context: context.Background()}

	_, err := IdentityBundle(nil, cred, opts)
	assert.ErrorContains(t, err, "content must not be nil")

	_, err = IdentityBundle(content, nil, opts)
	assert.ErrorContains(t, err, "credential must not be nil")

	b, err := IdentityBundle(content, cred, opts)
	assert.ErrorContains(t, err, "transparency log is required")
	assert.Nil(t, b)
}

func TestIdentityBundle_TlogError(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	cred := &OIDCCredential{Token: "fake-token"}
	opts := IdentityBundleOptions{
		Context:         context.Background(),
		TransparencyLog: &mockTlog{err: assert.AnError},
	}

	b, err := IdentityBundle(content, cred, opts)
	assert.ErrorIs(t, err, assert.AnError)
	assert.ErrorContains(t, err, "failed to get transparency log entry")
	assert.Nil(t, b)
}

type errorCred struct{}

func (e *errorCred) ToIdentityRequestV001(_ context.Context, _ []byte) (*pbrekor.IdentityRequestV001, error) {
	return nil, assert.AnError
}

func TestIdentityBundle_CredentialError(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	opts := IdentityBundleOptions{
		Context:         context.Background(),
		TransparencyLog: &mockTlog{},
	}

	b, err := IdentityBundle(content, &errorCred{}, opts)
	assert.ErrorIs(t, err, assert.AnError)
	assert.ErrorContains(t, err, "failed to create identity request")
	assert.Nil(t, b)
}

func TestIdentityBundle_OIDCCredential(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	cred := &OIDCCredential{Token: "fake-token"}
	opts := IdentityBundleOptions{
		Context:         context.Background(),
		TransparencyLog: &mockTlog{},
	}

	b, err := IdentityBundle(content, cred, opts)
	require.NoError(t, err)
	require.NotNil(t, b)

	// OIDC sets TransparencyLogProof with an unset Signature and nil Payload for raw artifacts
	assert.Nil(t, b.GetPayload())
	require.NotNil(t, b.VerificationMaterial.GetTransparencyLogProof())
	assert.Nil(t, b.VerificationMaterial.GetTransparencyLogProof().GetSignature())
	assert.Equal(t, []byte("mock-proof"), b.VerificationMaterial.GetTransparencyLogProof().Proof)

	bv2, err := verifyBundle.NewBundleV2(b)
	require.NoError(t, err)
	assert.False(t, bv2.HasEnvelope())
	sig, err := bv2.Signature()
	require.NoError(t, err)
	assert.Nil(t, sig)

	// OIDC with DSSEData sets Payload and leaves TransparencyLogProof.Signature unset
	dsseContent := &DSSEData{
		Data:        []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
		PayloadType: "application/vnd.in-toto+json",
	}
	dsseBundle, err := IdentityBundle(dsseContent, cred, opts)
	require.NoError(t, err)
	require.NotNil(t, dsseBundle.GetPayload())
	assert.Nil(t, dsseBundle.VerificationMaterial.GetTransparencyLogProof().GetSignature())

	dsseBv2, err := verifyBundle.NewBundleV2(dsseBundle)
	require.NoError(t, err)
	assert.True(t, dsseBv2.HasEnvelope())
	dsseSig, err := dsseBv2.Signature()
	require.NoError(t, err)
	assert.Nil(t, dsseSig)
}

type verifiableMockTlog struct {
	logPrivKey *mldsa.PrivateKey
	origin     string
}

func (m *verifiableMockTlog) GetIdentityTransparencyLogEntry(ctx context.Context, req *pbrekor.IdentityRequestV001) (*bundleV2.TransparencyLogProof, error) {
	msgHash := sha256.Sum256(req.GetMessage())

	var rotHash [32]byte
	var receiptDigest [32]byte
	var contextHashes []byte
	var extraData []byte

	if pk := req.GetPublicKey(); pk != nil {
		rot := append([]byte("ML-DSA-44"), pk.GetPublicKey()...)
		rotHash = sha256.Sum256(rot)
		receiptDigest = sha256.Sum256(pk.GetSignature())
		if len(pk.GetContext()) > 0 {
			extraData = []byte("context:" + hex.EncodeToString(pk.GetContext()))
			k1 := sha256.Sum256([]byte("context"))
			k2 := sha256.Sum256(k1[:])
			v2 := sha256.Sum256(pk.GetContext())
			contextHashes = append(contextHashes, k2[:]...)
			contextHashes = append(contextHashes, v2[:]...)
		}
	} else {
		extraData = []byte("identity:foo@bar.com\nissuer:https://example.com")
		rotHash = sha256.Sum256([]byte("https://example.com"))
		ik1 := sha256.Sum256([]byte("identity"))
		ik2 := sha256.Sum256(ik1[:])
		iv1 := sha256.Sum256([]byte("foo@bar.com"))
		iv2 := sha256.Sum256(iv1[:])
		issk1 := sha256.Sum256([]byte("issuer"))
		issk2 := sha256.Sum256(issk1[:])
		issv1 := sha256.Sum256([]byte("https://example.com"))
		issv2 := sha256.Sum256(issv1[:])
		if bytes.Compare(ik2[:], issk2[:]) < 0 {
			contextHashes = append(contextHashes, ik2[:]...)
			contextHashes = append(contextHashes, iv2[:]...)
			contextHashes = append(contextHashes, issk2[:]...)
			contextHashes = append(contextHashes, issv2[:]...)
		} else {
			contextHashes = append(contextHashes, issk2[:]...)
			contextHashes = append(contextHashes, issv2[:]...)
			contextHashes = append(contextHashes, ik2[:]...)
			contextHashes = append(contextHashes, iv2[:]...)
		}
	}

	leaf := []byte{0x01}
	leaf = append(leaf, rotHash[:]...)
	leaf = append(leaf, msgHash[:]...)
	leaf = append(leaf, contextHashes...)
	leaf = append(leaf, receiptDigest[:]...)
	leafHash := rfc6962.DefaultHasher.HashLeaf(leaf)

	cp := formatsLog.Checkpoint{
		Origin: m.origin,
		Size:   1,
		Hash:   leafHash,
	}
	signer, err := signature.LoadDefaultSigner(m.logPrivKey)
	if err != nil {
		return nil, err
	}
	noteSigner, err := note.NewNoteSigner(ctx, m.origin, signer)
	if err != nil {
		return nil, err
	}
	signedNote, err := sumdbNote.Sign(&sumdbNote.Note{Text: string(cp.Marshal())}, noteSigner)
	if err != nil {
		return nil, err
	}

	tlogProof := proof.TLogProof{
		Index:      0,
		Checkpoint: signedNote,
		ExtraData:  extraData,
	}
	return &bundleV2.TransparencyLogProof{
		Proof: tlogProof.Marshal(),
	}, nil
}

type mockSignTrustedMaterial struct {
	root.BaseTrustedMaterial
	rekorLog  *root.TransparencyLog
	verifiers []root.TimeConstrainedVerifier
}

func (m *mockSignTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{"log": m.rekorLog}
}

func (m *mockSignTrustedMaterial) PublicKeyVerifiers() []root.TimeConstrainedVerifier {
	return m.verifiers
}

func TestIdentityBundle_TrustedRoot(t *testing.T) {
	logPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)

	keypair, err := NewMLDSAKeypair()
	require.NoError(t, err)

	verifier, err := signature.LoadVerifier(keypair.GetPublicKey(), crypto.Hash(0))
	require.NoError(t, err)

	tm := &mockSignTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:   "https://rekor-local",
			PublicKey: logPrivKey.Public(),
		},
		verifiers: []root.TimeConstrainedVerifier{
			root.NewExpiringKey(verifier, time.Time{}, time.Time{}),
		},
	}

	tlog := &verifiableMockTlog{
		logPrivKey: logPrivKey,
		origin:     "rekor-local",
	}
	content := &PlainData{Data: []byte("hello world")}

	// 1. PublicKeyCredential without Context
	b, err := IdentityBundle(content, &PublicKeyCredential{Keypair: keypair}, IdentityBundleOptions{
		TransparencyLog: tlog,
		TrustedRoot:     tm,
	})
	require.NoError(t, err)
	require.NotNil(t, b)

	// 2. PublicKeyCredential with 32-byte Context
	ctxDigest := sha256.Sum256([]byte("test-context"))
	b, err = IdentityBundle(content, &PublicKeyCredential{Keypair: keypair, Context: ctxDigest[:]}, IdentityBundleOptions{
		TransparencyLog: tlog,
		TrustedRoot:     tm,
	})
	require.NoError(t, err)
	require.NotNil(t, b)

	// 3. OIDCCredential
	b, err = IdentityBundle(content, &OIDCCredential{Token: "fake-token"}, IdentityBundleOptions{
		TransparencyLog: tlog,
		TrustedRoot:     tm,
	})
	require.NoError(t, err)
	require.NotNil(t, b)
}
