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
	"errors"
	"fmt"

	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
)

// IdentityCredential represents credentials submitted to the transparency log.
type IdentityCredential interface {
	// ToIdentityRequestV001 constructs an IdentityRequestV001 for the given artifact digest.
	ToIdentityRequestV001(ctx context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error)
}

var _ IdentityCredential = (*OIDCCredential)(nil)
var _ IdentityCredential = (*PublicKeyCredential)(nil)

// OIDCCredential authenticates to the transparency log using an OpenID Connect identity token.
type OIDCCredential struct {
	Token string
}

// ToIdentityRequestV001 constructs an IdentityRequestV001 containing the OIDC identity token and artifact digest.
func (c *OIDCCredential) ToIdentityRequestV001(_ context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error) {
	if c.Token == "" {
		return nil, errors.New("OIDC token must not be empty")
	}
	if len(messageDigest) != sha256.Size {
		return nil, fmt.Errorf("message digest must be a %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(messageDigest))
	}
	return &pbrekor.IdentityRequestV001{
		Credential: &pbrekor.IdentityRequestV001_Oidc{
			Oidc: &pbrekor.OidcCredential{
				Token: c.Token,
			},
		},
		Message: messageDigest, // First hash: SHA256(artifact)
	}, nil
}

// PublicKeyCredential authenticates to the transparency log using a public key and
// domain-separated signature over the artifact digest and optional context.
type PublicKeyCredential struct {
	Keypair Keypair
	// Context is an optional 32-byte SHA-256 digest bound into the signature and log entry.
	Context []byte
}

// ToIdentityRequestV001 signs the domain-separated message digest and optional context and constructs an IdentityRequestV001.
func (c *PublicKeyCredential) ToIdentityRequestV001(ctx context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error) {
	if c.Keypair == nil {
		return nil, errors.New("keypair must not be nil")
	}
	if len(messageDigest) != sha256.Size {
		return nil, fmt.Errorf("message digest must be a %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(messageDigest))
	}
	if len(c.Context) > 0 && len(c.Context) != sha256.Size {
		return nil, fmt.Errorf("context must be a %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(c.Context))
	}

	pubKey := c.Keypair.GetPublicKey()
	mldsaKey, ok := pubKey.(*mldsa.PublicKey)
	if !ok || mldsaKey.Parameters() != mldsa.MLDSA44() {
		return nil, errors.New("public key must be an ML-DSA-44 key")
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	prehashedData := identitySigningPayload(messageDigest, c.Context)
	sig, _, err := c.Keypair.SignData(ctx, prehashedData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &pbrekor.IdentityRequestV001{
		Credential: &pbrekor.IdentityRequestV001_PublicKey{
			PublicKey: &pbrekor.PublicKeyCredential{
				PublicKey: pubKeyBytes,
				Signature: sig,
				Context:   c.Context,
			},
		},
		Message: messageDigest, // First hash: SHA256(artifact)
	}, nil
}

const (
	identityTransparencyDomainSeparator = "c2sp.org/identity-transparency/v1\x00"
	contextClaimKey                     = "context"
)

// identitySigningPayload constructs c2sp.org/identity-transparency/v1 || 0x00 || SHA256(messageDigest) [|| SHA256(SHA256("context")) || SHA256(context)].
func identitySigningPayload(messageDigest, ctxDigest []byte) []byte {
	doubleHash := sha256.Sum256(messageDigest)
	payload := append([]byte(identityTransparencyDomainSeparator), doubleHash[:]...)
	if len(ctxDigest) > 0 {
		k1 := sha256.Sum256([]byte(contextClaimKey))
		kDoubleHash := sha256.Sum256(k1[:])
		vDoubleHash := sha256.Sum256(ctxDigest)
		payload = append(payload, kDoubleHash[:]...)
		payload = append(payload, vDoubleHash[:]...)
	}
	return payload
}
