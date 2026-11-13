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
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCCredential(t *testing.T) {
	cred := &OIDCCredential{Token: "test-token"}
	digest := sha256.Sum256([]byte("artifact"))

	req, err := cred.ToIdentityRequestV001(context.Background(), digest[:])
	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, digest[:], req.Message)
	require.NotNil(t, req.GetOidc())
	assert.Equal(t, "test-token", req.GetOidc().Token)

	emptyCred := &OIDCCredential{}
	_, err = emptyCred.ToIdentityRequestV001(context.Background(), digest[:])
	assert.ErrorContains(t, err, "OIDC token must not be empty")

	_, err = cred.ToIdentityRequestV001(context.Background(), []byte("not-32-bytes"))
	assert.ErrorContains(t, err, "message digest must be a 32-byte SHA-256 digest")
}

func TestPublicKeyCredential(t *testing.T) {
	keypair, err := NewMLDSAKeypair()
	require.NoError(t, err)

	ctxDigest := sha256.Sum256([]byte("test-context"))
	cred := &PublicKeyCredential{
		Keypair: keypair,
		Context: ctxDigest[:],
	}
	digest := sha256.Sum256([]byte("artifact"))

	req, err := cred.ToIdentityRequestV001(context.Background(), digest[:])
	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, digest[:], req.Message)
	require.NotNil(t, req.GetPublicKey())
	assert.NotEmpty(t, req.GetPublicKey().Signature)
	assert.Equal(t, ctxDigest[:], req.GetPublicKey().Context)

	// Verify the public key and signature in the request
	parsedPub, err := x509.ParsePKIXPublicKey(req.GetPublicKey().PublicKey)
	require.NoError(t, err)
	mldsaPub, ok := parsedPub.(*mldsa.PublicKey)
	require.True(t, ok)

	doubleHash := sha256.Sum256(digest[:])
	k1 := sha256.Sum256([]byte("context"))
	kDoubleHash := sha256.Sum256(k1[:])
	vDoubleHash := sha256.Sum256(ctxDigest[:])
	expectedMsg := append([]byte("c2sp.org/identity-transparency/v1\x00"), doubleHash[:]...)
	expectedMsg = append(expectedMsg, kDoubleHash[:]...)
	expectedMsg = append(expectedMsg, vDoubleHash[:]...)
	assert.NoError(t, mldsa.Verify(mldsaPub, expectedMsg, req.GetPublicKey().Signature, nil))

	nilCred := &PublicKeyCredential{}
	_, err = nilCred.ToIdentityRequestV001(context.Background(), digest[:])
	assert.ErrorContains(t, err, "keypair must not be nil")

	_, err = cred.ToIdentityRequestV001(context.Background(), []byte("not-32-bytes"))
	assert.ErrorContains(t, err, "message digest must be a 32-byte SHA-256 digest")

	badCtxCred := &PublicKeyCredential{
		Keypair: keypair,
		Context: []byte("not-32-bytes"),
	}
	_, err = badCtxCred.ToIdentityRequestV001(context.Background(), digest[:])
	assert.ErrorContains(t, err, "context must be a 32-byte SHA-256 digest")

	ecdsaKeypair, err := NewEphemeralKeypair(nil)
	require.NoError(t, err)
	nonMLDSACred := &PublicKeyCredential{
		Keypair: ecdsaKeypair,
	}
	_, err = nonMLDSACred.ToIdentityRequestV001(context.Background(), digest[:])
	assert.ErrorContains(t, err, "public key must be an ML-DSA-44 key")
}
