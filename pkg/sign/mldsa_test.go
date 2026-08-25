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
	"strings"
	"testing"

	"filippo.io/mldsa"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
)

func TestMLDSAKeypair_Generate(t *testing.T) {
	keypair, err := NewMLDSAKeypair()
	assert.NoError(t, err)
	assert.NotNil(t, keypair)
	assert.NotNil(t, keypair.privKey)
	assert.NotEmpty(t, keypair.hint)
}

func TestMLDSAKeypair_Properties(t *testing.T) {
	keypair, err := NewMLDSAKeypair()
	assert.NoError(t, err)

	assert.Equal(t, protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED, keypair.GetHashAlgorithm())
	assert.Equal(t, protocommon.PublicKeyDetails_ML_DSA_44, keypair.GetSigningAlgorithm())
	assert.Equal(t, "ML-DSA-44", keypair.GetKeyAlgorithm())
	assert.NotEmpty(t, keypair.GetHint())
	assert.NotNil(t, keypair.GetPublicKey())

	pemStr, err := keypair.GetPublicKeyPem()
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(pemStr, "-----BEGIN PUBLIC KEY-----"))
	assert.True(t, strings.Contains(pemStr, "-----END PUBLIC KEY-----"))
}

func TestMLDSAKeypair_Sign(t *testing.T) {
	keypair, err := NewMLDSAKeypair()
	assert.NoError(t, err)

	data := []byte("test data to sign")
	sig, retData, err := keypair.SignData(context.Background(), data)
	assert.NoError(t, err)
	assert.Equal(t, data, retData)
	assert.NotEmpty(t, sig)

	pubKey := keypair.GetPublicKey().(*mldsa.PublicKey)
	err = mldsa.Verify(pubKey, data, sig, nil)
	assert.NoError(t, err)
}
