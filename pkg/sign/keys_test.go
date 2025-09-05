// Copyright 2024 The Sigstore Authors.
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
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
)

func Test_EphemeralKeypair(t *testing.T) {
	// Test hint logic
	t.Run("hint", func(t *testing.T) {
		// with hint
		opts := &EphemeralKeypairOptions{
			Hint: []byte("asdf"),
		}
		ephemeralKeypair, err := NewEphemeralKeypair(opts)
		assert.NotNil(t, ephemeralKeypair)
		assert.Nil(t, err)
		hint := ephemeralKeypair.GetHint()
		assert.Equal(t, hint, []byte("asdf"))

		// without hint (default)
		defaultEphemeralKeypair, err := NewEphemeralKeypair(nil)
		assert.Nil(t, err)
		hint = defaultEphemeralKeypair.GetHint()
		assert.NotEqual(t, hint, []byte(""))
	})

	// Test different algorithms
	testCases := []struct {
		name             string
		algorithm        protocommon.PublicKeyDetails
		expectedKeyAlgo  string
		expectedHashAlgo protocommon.HashAlgorithm
		cryptoHash       crypto.Hash
	}{
		{
			name:             "default (ECDSA P-256)",
			algorithm:        protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED,
			expectedKeyAlgo:  "ECDSA",
			expectedHashAlgo: protocommon.HashAlgorithm_SHA2_256,
			cryptoHash:       crypto.SHA256,
		},
		{
			name:             "ECDSA P-384",
			algorithm:        protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
			expectedKeyAlgo:  "ECDSA",
			expectedHashAlgo: protocommon.HashAlgorithm_SHA2_384,
			cryptoHash:       crypto.SHA384,
		},
		{
			name:             "ECDSA P-521",
			algorithm:        protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
			expectedKeyAlgo:  "ECDSA",
			expectedHashAlgo: protocommon.HashAlgorithm_SHA2_512,
			cryptoHash:       crypto.SHA512,
		},
		{
			name:             "RSA PKCS#1 v1.5 2048",
			algorithm:        protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
			expectedKeyAlgo:  "RSA",
			expectedHashAlgo: protocommon.HashAlgorithm_SHA2_256,
			cryptoHash:       crypto.SHA256,
		},
		{
			name:             "RSA PKCS#1 v1.5 4096",
			algorithm:        protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256,
			expectedKeyAlgo:  "RSA",
			expectedHashAlgo: protocommon.HashAlgorithm_SHA2_256,
			cryptoHash:       crypto.SHA256,
		},
		{
			name:             "ED25519",
			algorithm:        protocommon.PublicKeyDetails_PKIX_ED25519,
			expectedKeyAlgo:  "ED25519",
			expectedHashAlgo: protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
			cryptoHash:       crypto.Hash(0),
		},
		{
			name:             "ED25519ph",
			algorithm:        protocommon.PublicKeyDetails_PKIX_ED25519_PH,
			expectedKeyAlgo:  "ED25519",
			expectedHashAlgo: protocommon.HashAlgorithm_SHA2_512,
			cryptoHash:       crypto.SHA512,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			opts := &EphemeralKeypairOptions{
				Algorithm: tc.algorithm,
			}

			ephemeralKeypair, err := NewEphemeralKeypair(opts)
			assert.NotNil(t, ephemeralKeypair)
			assert.Nil(t, err)

			hashAlgorithm := ephemeralKeypair.GetHashAlgorithm()
			assert.Equal(t, tc.expectedHashAlgo, hashAlgorithm)

			signingAlgorithm := ephemeralKeypair.GetSigningAlgorithm()
			expectedAlg := tc.algorithm
			if tc.algorithm == protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED {
				expectedAlg = protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
			}
			assert.Equal(t, expectedAlg, signingAlgorithm)

			keyAlgorithm := ephemeralKeypair.GetKeyAlgorithm()
			assert.Equal(t, tc.expectedKeyAlgo, keyAlgorithm)

			pubKey := ephemeralKeypair.GetPublicKey()
			assert.NotNil(t, pubKey)

			pem, err := ephemeralKeypair.GetPublicKeyPem()
			assert.NotEqual(t, pem, "")
			assert.Nil(t, err)

			dataToSign := []byte("hello world")
			signatureBytes, digest, err := ephemeralKeypair.SignData(ctx, dataToSign)
			assert.NotNil(t, signatureBytes)
			assert.NotNil(t, digest)
			assert.Nil(t, err)

			// verify signature
			var loadOpts []signature.LoadOption
			loadOpts = append(loadOpts, options.WithHash(tc.cryptoHash))
			if tc.algorithm == protocommon.PublicKeyDetails_PKIX_ED25519_PH {
				loadOpts = append(loadOpts, options.WithED25519ph())
			}
			verifier, err := signature.LoadVerifierWithOpts(pubKey, loadOpts...)
			assert.Nil(t, err)
			err = verifier.VerifySignature(bytes.NewReader(signatureBytes), bytes.NewReader(dataToSign))
			assert.Nil(t, err)
		})
	}

	t.Run("unsupported algorithm", func(t *testing.T) {
		unsupportedAlgorithms := []protocommon.PublicKeyDetails{
			protocommon.PublicKeyDetails(999), // An arbitrary invalid value
		}

		for _, alg := range unsupportedAlgorithms {
			opts := &EphemeralKeypairOptions{Algorithm: alg}
			_, err := NewEphemeralKeypair(opts)
			assert.Error(t, err)
		}
	})
}
