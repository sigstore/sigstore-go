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
	"testing"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/stretchr/testify/assert"
)

type mockTlog struct{}

func (m *mockTlog) GetIdentityTransparencyLogEntry(_ context.Context, _ IdentityCredential, _ []byte) (*bundleV2.TlogProof, error) {
	return &bundleV2.TlogProof{
		Proof: []byte("mock-proof"),
	}, nil
}

func TestIdentityBundle(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}

	keypair, err := NewMLDSAKeypair()
	assert.NoError(t, err)

	cred := &PublicKeyCredential{
		Keypair: keypair,
	}

	opts := IdentityBundleOptions{
		Context:          context.Background(),
		TransparencyLogs: []IdentityTransparencyLog{&mockTlog{}},
	}

	bundle, err := IdentityBundle(content, cred, opts)
	assert.NoError(t, err)
	assert.NotNil(t, bundle)
	assert.Equal(t, "application/vnd.dev.sigstore.bundle.v2.0+json", bundle.MediaType)
	assert.NotNil(t, bundle.VerificationMaterial.GetTlogProof())
	assert.Equal(t, []byte("mock-proof"), bundle.VerificationMaterial.GetTlogProof().Proof)
}

type errorTlog struct{}

func (e *errorTlog) GetIdentityTransparencyLogEntry(_ context.Context, _ IdentityCredential, _ []byte) (*bundleV2.TlogProof, error) {
	return nil, assert.AnError
}

func TestIdentityBundle_NoTlog(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	keypair, _ := NewMLDSAKeypair()
	cred := &PublicKeyCredential{Keypair: keypair}
	opts := IdentityBundleOptions{Context: context.Background()}

	bundle, err := IdentityBundle(content, cred, opts)
	assert.ErrorContains(t, err, "at least one transparency log is required")
	assert.Nil(t, bundle)
}

func TestIdentityBundle_TlogError(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	keypair, _ := NewMLDSAKeypair()
	cred := &PublicKeyCredential{Keypair: keypair}
	opts := IdentityBundleOptions{
		Context:          context.Background(),
		TransparencyLogs: []IdentityTransparencyLog{&errorTlog{}},
	}

	bundle, err := IdentityBundle(content, cred, opts)
	assert.ErrorIs(t, err, assert.AnError)
	assert.ErrorContains(t, err, "failed to get transparency log entry")
	assert.Nil(t, bundle)
}

type errorCred struct {
	*PublicKeyCredential
}

func (e *errorCred) ArtifactSignature(_ context.Context, _ []byte) ([]byte, error) {
	return nil, assert.AnError
}

func TestIdentityBundle_ArtifactSigError(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	keypair, _ := NewMLDSAKeypair()
	cred := &errorCred{PublicKeyCredential: &PublicKeyCredential{Keypair: keypair}}
	opts := IdentityBundleOptions{
		Context:          context.Background(),
		TransparencyLogs: []IdentityTransparencyLog{&mockTlog{}},
	}

	bundle, err := IdentityBundle(content, cred, opts)
	assert.ErrorIs(t, err, assert.AnError)
	assert.ErrorContains(t, err, "failed to generate artifact signature")
	assert.Nil(t, bundle)
}

func TestIdentityBundle_OIDCCredential(t *testing.T) {
	content := &PlainData{Data: []byte("hello world")}
	cred := &OIDCCredential{Token: "fake-token"}
	opts := IdentityBundleOptions{
		Context:          context.Background(),
		TransparencyLogs: []IdentityTransparencyLog{&mockTlog{}},
	}

	bundle, err := IdentityBundle(content, cred, opts)
	assert.NoError(t, err)
	assert.NotNil(t, bundle)

	// OIDC doesn't provide an artifact signature in bundle.Content
	assert.Nil(t, bundle.Content)
	assert.NotNil(t, bundle.VerificationMaterial.GetTlogProof())
	assert.Equal(t, []byte("mock-proof"), bundle.VerificationMaterial.GetTlogProof().Proof)
	assert.Nil(t, bundle.VerificationMaterial.GetTlogProof().PublicKey) // No public key for OIDC in bundle creation
}
