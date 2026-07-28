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
	"fmt"

	mldsax509 "filippo.io/mldsa/x509"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
)

// IdentityCredential represents credentials submitted to the transparency log.
type IdentityCredential interface {
	ToIdentityRequestV001(ctx context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error)
	ArtifactSignature(ctx context.Context, messageDigest []byte) ([]byte, error)
}

type OIDCCredential struct {
	Token string
}

func (c *OIDCCredential) ArtifactSignature(_ context.Context, _ []byte) ([]byte, error) {
	return nil, nil
}

func (c *OIDCCredential) ToIdentityRequestV001(_ context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error) {
	return &pbrekor.IdentityRequestV001{
		Credential: &pbrekor.IdentityRequestV001_Oidc{
			Oidc: &pbrekor.OidcCredential{
				Token: c.Token,
			},
		},
		Message: messageDigest, // First hash: SHA256(artifact)
	}, nil
}

type PublicKeyCredential struct {
	Keypair         Keypair
	Context         []byte
	cachedSignature []byte
}

func (c *PublicKeyCredential) ArtifactSignature(ctx context.Context, messageDigest []byte) ([]byte, error) {
	if c.cachedSignature != nil {
		return c.cachedSignature, nil
	}

	// c2sp.org/identity-transparency/v1 || 0x00 || SHA256(messageDigest)
	doubleHash := sha256.Sum256(messageDigest)
	prehashedData := append([]byte("c2sp.org/identity-transparency/v1\x00"), doubleHash[:]...)

	sig, _, err := c.Keypair.SignData(ctx, prehashedData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	c.cachedSignature = sig
	return sig, nil
}

func (c *PublicKeyCredential) ToIdentityRequestV001(ctx context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error) {
	pubKeyBytes, err := mldsax509.MarshalPKIXPublicKey(c.Keypair.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	sig, err := c.ArtifactSignature(ctx, messageDigest)
	if err != nil {
		return nil, err
	}

	return &pbrekor.IdentityRequestV001{
		Credential: &pbrekor.IdentityRequestV001_PublicKey{
			PublicKey: &pbrekor.PublicKeyCredential{
				PublicKey: pubKeyBytes,
				Signature: sig,
				Context:   c.Context,
				Algorithm: c.Keypair.GetSigningAlgorithm(),
			},
		},
		Message: messageDigest, // First hash: SHA256(artifact)
	}, nil
}
