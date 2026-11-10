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

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type IdentityBundleOptions struct {
	// TransparencyLog to submit the entry to and obtain a c2sp.org/tlog-proof from.
	TransparencyLog IdentityTransparencyLog
	// Optional context for network requests.
	Context context.Context
	// Optional trusted root to verify the signed bundle.
	TrustedRoot root.TrustedMaterial
}

// IdentityBundle creates a Bundle V2 using the transparent signature flow
// with either an OIDC token or a public key credential.
func IdentityBundle(_ Content, _ IdentityCredential, _ IdentityBundleOptions) (*bundleV2.Bundle, error) {
	return nil, errors.New("not implemented")
}

type PKIBundleOptions struct {
	// CertificateProvider to obtain a single leaf code-signing certificate from (e.g. a Fulcio instance).
	CertificateProvider CertificateProvider
	// Optional CertificateChainProvider for private CA deployments with intermediate certificates.
	// Takes precedence over CertificateProvider and stores the leaf certificate and intermediates in the bundle.
	CertificateChainProvider CertificateChainProvider
	// Options for the certificate provider (such as the OIDC IDToken required by Fulcio).
	CertificateProviderOptions *CertificateProviderOptions
	// List of RFC 3161 timestamp authorities to timestamp the signature. At least one is required.
	TimestampAuthorities []*TimestampAuthority
	// Optional context for network requests.
	Context context.Context
	// Optional trusted root to verify the signed bundle.
	TrustedRoot root.TrustedMaterial
}

// PKIBundle creates a Bundle V2 using the PKI signing flow with a certificate authority
// and RFC 3161 timestamp authority.
func PKIBundle(_ Content, _ Keypair, _ PKIBundleOptions) (*bundleV2.Bundle, error) {
	return nil, errors.New("not implemented")
}

type KeyBundleOptions struct {
	// Optional list of timestamp authorities to contact for inclusion in bundle.
	TimestampAuthorities []*TimestampAuthority
	// Optional context for network requests.
	Context context.Context
	// Optional trusted root to verify the signed bundle.
	TrustedRoot root.TrustedMaterial
}

// KeyBundle creates a Bundle V2 using a managed signing keypair, with optional
// RFC 3161 timestamps and without logging to a transparency log.
func KeyBundle(_ Content, _ Keypair, _ KeyBundleOptions) (*bundleV2.Bundle, error) {
	return nil, errors.New("not implemented")
}
