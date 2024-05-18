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
	"crypto/sha512" // if user chooses SHA2-384 or SHA2-512 for hash
	"crypto/x509"
	"encoding/base64"
	"errors"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"golang.org/x/crypto/sha3"
)

type Keypair interface {
	GetHashAlgorithm() protocommon.HashAlgorithm
	GetHint() []byte
	GetKeyAlgorithm() string
	GetPublicKeyPem() (string, error)
	SignData(data []byte) ([]byte, []byte, error)
}

type EphemeralKeypairOptions struct {
	// Optional hint of for signing key
	Hint          []byte
	HashAlgorithm protocommon.HashAlgorithm
}

type EphemeralKeypair struct {
	options       *EphemeralKeypairOptions
	privateKey    *ecdsa.PrivateKey
	hashAlgorithm protocommon.HashAlgorithm
}

func NewEphemeralKeypair(opts *EphemeralKeypairOptions) (*EphemeralKeypair, error) {
	if opts == nil {
		opts = &EphemeralKeypairOptions{HashAlgorithm: protocommon.HashAlgorithm_SHA2_256}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	if opts.Hint == nil {
		switch opts.HashAlgorithm {
		case protocommon.HashAlgorithm_SHA2_384:
			hashedBytes := sha512.Sum384(pubKeyBytes)
			opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
		case protocommon.HashAlgorithm_SHA2_512:
			hashedBytes := sha512.Sum512(pubKeyBytes)
			opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
		case protocommon.HashAlgorithm_SHA3_256:
			hashedBytes := sha3.Sum256(pubKeyBytes)
			opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
		case protocommon.HashAlgorithm_SHA3_384:
			hashedBytes := sha3.Sum384(pubKeyBytes)
			opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
		default:
			hashedBytes := sha256.Sum256(pubKeyBytes)
			opts.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
		}
	}

	ephemeralKeypair := EphemeralKeypair{
		options:       opts,
		privateKey:    privateKey,
		hashAlgorithm: opts.HashAlgorithm,
	}

	return &ephemeralKeypair, nil
}

func (e *EphemeralKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return e.hashAlgorithm
}

func (e *EphemeralKeypair) GetHint() []byte {
	return e.options.Hint
}

func (e *EphemeralKeypair) GetKeyAlgorithm() string {
	return "ECDSA"
}

func (e *EphemeralKeypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(e.privateKey.Public())
	if err != nil {
		return "", err
	}

	return string(pubKeyBytes), nil
}

func getHashFunc(hashAlgorithm protocommon.HashAlgorithm) (crypto.Hash, error) {
	switch hashAlgorithm {
	case protocommon.HashAlgorithm_SHA2_256:
		return crypto.Hash(crypto.SHA256), nil
	case protocommon.HashAlgorithm_SHA2_384:
		return crypto.Hash(crypto.SHA384), nil
	case protocommon.HashAlgorithm_SHA2_512:
		return crypto.Hash(crypto.SHA512), nil
	case protocommon.HashAlgorithm_SHA3_256:
		return crypto.Hash(crypto.SHA3_256), nil
	case protocommon.HashAlgorithm_SHA3_384:
		return crypto.Hash(crypto.SHA3_384), nil
	default:
		var hash crypto.Hash
		return hash, errors.New("unsupported hash algorithm")
	}
}

func (e *EphemeralKeypair) SignData(data []byte) ([]byte, []byte, error) {
	hashFunc, err := getHashFunc(e.hashAlgorithm)
	if err != nil {
		return nil, nil, err
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
