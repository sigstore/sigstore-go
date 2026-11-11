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
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// MLDSAKeypair holds an ephemeral ML-DSA-44 signing keypair and its public key hint.
type MLDSAKeypair struct {
	hint    []byte
	privKey *mldsa.PrivateKey
}

var _ Keypair = (*MLDSAKeypair)(nil)

// NewMLDSAKeypair generates an ephemeral ML-DSA-44 signing keypair with a SHA-256 key hint.
func NewMLDSAKeypair() (*MLDSAKeypair, error) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, err
	}
	hashedBytes := sha256.Sum256(pubKeyBytes)
	hint := []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))

	return &MLDSAKeypair{
		hint:    hint,
		privKey: privKey,
	}, nil
}

// GetHashAlgorithm returns the hash algorithm to compute the digest to sign.
// ML-DSA signs messages directly without pre-hashing, so this returns HASH_ALGORITHM_UNSPECIFIED.
func (e *MLDSAKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
}

// GetSigningAlgorithm returns the signing algorithm of the key (ML_DSA_44).
func (e *MLDSAKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_ML_DSA_44
}

// GetHint returns the SHA-256 fingerprint of the public key.
// Note: key hints are not used in v2 bundles; this is only implemented to satisfy the Keypair interface.
func (e *MLDSAKeypair) GetHint() []byte {
	return e.hint
}

// GetKeyAlgorithm returns the top-level key algorithm name ("ML-DSA-44").
func (e *MLDSAKeypair) GetKeyAlgorithm() string {
	return "ML-DSA-44"
}

// GetPublicKey returns the ML-DSA public key.
func (e *MLDSAKeypair) GetPublicKey() crypto.PublicKey {
	return e.privKey.Public()
}

// GetPublicKeyPem returns the public key in PKIX PEM format.
func (e *MLDSAKeypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(e.privKey.Public())
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// SignData signs data directly with the ML-DSA-44 private key and returns the signature and signed data.
func (e *MLDSAKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	// ML-DSA signs data directly, not a pre-hashed digest.
	signature, err := e.privKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, nil, err
	}
	return signature, data, nil
}
