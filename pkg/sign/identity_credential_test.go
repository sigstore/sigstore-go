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

	"github.com/stretchr/testify/assert"
)

func TestOIDCCredential(t *testing.T) {
	cred := &OIDCCredential{Token: "test-token"}
	digest := sha256.Sum256([]byte("artifact"))

	sig, err := cred.ArtifactSignature(context.Background(), digest[:])
	assert.NoError(t, err)
	assert.Nil(t, sig)

	req, err := cred.ToIdentityRequestV001(context.Background(), digest[:])
	assert.NoError(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, digest[:], req.Message)
	assert.NotNil(t, req.GetOidc())
	assert.Equal(t, "test-token", req.GetOidc().Token)
}

func TestPublicKeyCredential(t *testing.T) {
	keypair, err := NewMLDSAKeypair()
	assert.NoError(t, err)

	cred := &PublicKeyCredential{
		Keypair: keypair,
		Context: []byte("test-context"),
	}
	digest := sha256.Sum256([]byte("artifact"))

	// Test caching
	sig1, err := cred.ArtifactSignature(context.Background(), digest[:])
	assert.NoError(t, err)
	assert.NotEmpty(t, sig1)

	sig2, err := cred.ArtifactSignature(context.Background(), digest[:])
	assert.NoError(t, err)
	assert.Equal(t, sig1, sig2) // Same signature cached

	req, err := cred.ToIdentityRequestV001(context.Background(), digest[:])
	assert.NoError(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, digest[:], req.Message)
	assert.NotNil(t, req.GetPublicKey())
	assert.Equal(t, sig1, req.GetPublicKey().Signature)
	assert.Equal(t, []byte("test-context"), req.GetPublicKey().Context)
	assert.Equal(t, keypair.GetSigningAlgorithm(), req.GetPublicKey().Algorithm)
}
