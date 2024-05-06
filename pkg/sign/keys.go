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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512" // if user chooses SHA2-384 or SHA2-512 for hash
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

type Keypair interface {
	GetHashAlgorithm() protocommon.HashAlgorithm
	GetHint() []byte
	GetKeyAlgorithm() string
	GetPublicKeyPem() (string, error)
	SignData(data []byte) ([]byte, []byte, error)
}

type EphemeralKeypairOptions struct {
	// Optional hash algorithm to use to create digest of data provided to sign
	HashAlgorithm protocommon.HashAlgorithm
	// Optional hint of for signing key
	Hint []byte
}

type EphemeralKeypair struct {
	options    *EphemeralKeypairOptions
	privateKey *ecdsa.PrivateKey
}

func NewEphemeralKeypair(opts *EphemeralKeypairOptions) (*EphemeralKeypair, error) {
	if opts == nil {
		opts = &EphemeralKeypairOptions{}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	if opts.HashAlgorithm == protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED {
		opts.HashAlgorithm = protocommon.HashAlgorithm_SHA2_256
	}

	if opts.Hint == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)
		opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
	}

	ephemeralKeypair := EphemeralKeypair{
		options:    opts,
		privateKey: privateKey,
	}

	return &ephemeralKeypair, nil
}

func (e *EphemeralKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return e.options.HashAlgorithm
}

func (e *EphemeralKeypair) GetHint() []byte {
	return e.options.Hint
}

func (e *EphemeralKeypair) GetKeyAlgorithm() string {
	return "ECDSA"
}

func (e *EphemeralKeypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(e.privateKey.Public())
	if err != nil {
		return "", err
	}

	pemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(&pemBlock)), nil
}

func (e *EphemeralKeypair) SignData(data []byte) ([]byte, []byte, error) {
	var hashFunc crypto.Hash

	switch e.options.HashAlgorithm {
	case protocommon.HashAlgorithm_SHA2_256:
		hashFunc = crypto.Hash(crypto.SHA256)
	case protocommon.HashAlgorithm_SHA2_384:
		hashFunc = crypto.Hash(crypto.SHA384)
	case protocommon.HashAlgorithm_SHA2_512:
		hashFunc = crypto.Hash(crypto.SHA512)
	default:
		return nil, nil, errors.New("Unsupported hash algorithm")
	}

	hasher := hashFunc.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := e.privateKey.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return nil, nil, err
	}

	return signature, digest, nil
}
