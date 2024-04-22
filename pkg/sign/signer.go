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
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512" // if user chooses SHA2-384 or SHA2-512 for hash
	"crypto/x509"
	"encoding/base64"
	"errors"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

type Signer interface {
	Sign(data []byte) (*protobundle.Bundle, error)
}

// TODO: implement
// type Fulcio struct {
//	baseURL       string
//	identityToken string
// }

// func (f *Fulcio) Sign(data []byte) (*protobundle.Bundle, error) {}

type Keypair struct {
	options *KeypairOptions
}

type KeypairOptions struct {
	// Object that supports crypto.Signer.Sign, like crypto.PrivateKey
	Signer crypto.Signer
	// Hash algorithm to use to create digest of data provided to sign
	HashAlgorithm protocommon.HashAlgorithm
	// Optional hint of which signing key was used; will be included in bundle
	PublicKeyHint []byte
}

func SignerKeypair(opts *KeypairOptions) (*Keypair, error) {
	if opts.PublicKeyHint == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(opts.Signer.Public())
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)
		opts.PublicKeyHint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
	}

	return &Keypair{options: opts}, nil
}

func (k Keypair) Sign(data []byte) (*protobundle.Bundle, error) {
	bundle := protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: string(k.options.PublicKeyHint),
				},
			},
		},
	}

	var hashFunc crypto.Hash

	switch k.options.HashAlgorithm {
	case protocommon.HashAlgorithm_SHA2_256:
		hashFunc = crypto.Hash(crypto.SHA256)
	case protocommon.HashAlgorithm_SHA2_384:
		hashFunc = crypto.Hash(crypto.SHA384)
	case protocommon.HashAlgorithm_SHA2_512:
		hashFunc = crypto.Hash(crypto.SHA512)
	default:
		return nil, errors.New("Unsupported hash algorithm")
	}

	hasher := hashFunc.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := k.options.Signer.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return nil, err
	}

	bundle.Content = &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: k.options.HashAlgorithm,
				Digest:    digest,
			},
			Signature: signature,
		},
	}

	return &bundle, nil
}
