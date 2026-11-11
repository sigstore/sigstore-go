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
	"context"
	"crypto/sha256"
	"testing"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	verifyBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestIdentityBundle_TrustedRoot(t *testing.T) {
	keypair, err := NewMLDSAKeypair()
	require.NoError(t, err)

	tm := &root.BaseTrustedMaterial{}
	tlog := &mockTlog{}
	content := &PlainData{Data: []byte("hello world")}

	// 1. PublicKeyCredential without Context
	_, err = IdentityBundle(content, &PublicKeyCredential{Keypair: keypair}, IdentityBundleOptions{
		TransparencyLog: tlog,
		TrustedRoot:     tm,
	})
	assert.ErrorContains(t, err, "not implemented")

	// 2. PublicKeyCredential with 32-byte Context
	ctxDigest := sha256.Sum256([]byte("test-context"))
	_, err = IdentityBundle(content, &PublicKeyCredential{Keypair: keypair, Context: ctxDigest[:]}, IdentityBundleOptions{
		TransparencyLog: tlog,
		TrustedRoot:     tm,
	})
	assert.ErrorContains(t, err, "not implemented")

	// 3. OIDCCredential
	_, err = IdentityBundle(content, &OIDCCredential{Token: "fake-token"}, IdentityBundleOptions{
		TransparencyLog: tlog,
		TrustedRoot:     tm,
	})
	assert.ErrorContains(t, err, "not implemented")
}
