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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"

	"filippo.io/mldsa"
	mldsax509 "filippo.io/mldsa/x509"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

type MLDSAKeypair struct {
	hint    []byte
	privKey *mldsa.PrivateKey
}

func NewMLDSAKeypair() (*MLDSAKeypair, error) {
	privKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := mldsax509.MarshalPKIXPublicKey(privKey.Public())
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

func (e *MLDSAKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
}

func (e *MLDSAKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_ML_DSA_44
}

func (e *MLDSAKeypair) GetHint() []byte {
	return e.hint
}

func (e *MLDSAKeypair) GetKeyAlgorithm() string {
	return "ML-DSA-44"
}

func (e *MLDSAKeypair) GetPublicKey() crypto.PublicKey {
	return e.privKey.Public()
}

func (e *MLDSAKeypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := mldsax509.MarshalPKIXPublicKey(e.privKey.Public())
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func (e *MLDSAKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	// MLDSA signs data directly, not a digest. We pass it as the message.
	signature, err := e.privKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, nil, err
	}
	return signature, data, nil
}
