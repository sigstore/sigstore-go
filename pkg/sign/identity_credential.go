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
	"errors"

	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
)

// IdentityCredential represents credentials submitted to the transparency log.
type IdentityCredential interface {
	ToIdentityRequestV001(ctx context.Context, messageDigest []byte) (*pbrekor.IdentityRequestV001, error)
}

var _ IdentityCredential = (*OIDCCredential)(nil)
var _ IdentityCredential = (*PublicKeyCredential)(nil)

// OIDCCredential authenticates to the transparency log using an OpenID Connect identity token.
type OIDCCredential struct {
	Token string
}

func (c *OIDCCredential) ToIdentityRequestV001(_ context.Context, _ []byte) (*pbrekor.IdentityRequestV001, error) {
	return nil, errors.New("not implemented")
}

// PublicKeyCredential authenticates to the transparency log using a public key and
// domain-separated signature over the artifact digest and optional context.
type PublicKeyCredential struct {
	Keypair Keypair
	// Context is an optional 32-byte SHA-256 digest bound into the signature and log entry.
	Context []byte
}

func (c *PublicKeyCredential) ToIdentityRequestV001(_ context.Context, _ []byte) (*pbrekor.IdentityRequestV001, error) {
	return nil, errors.New("not implemented")
}
