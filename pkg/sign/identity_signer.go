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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	verifyBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const bundleV20MediaType = "application/vnd.dev.sigstore.bundle.v2.0+json"

// IdentityBundleOptions configures the IdentityBundle signing flow.
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
func IdentityBundle(content Content, cred IdentityCredential, opts IdentityBundleOptions) (*bundleV2.Bundle, error) {
	if content == nil {
		return nil, errors.New("content must not be nil")
	}
	if cred == nil {
		return nil, errors.New("credential must not be nil")
	}
	if opts.TransparencyLog == nil {
		return nil, errors.New("transparency log is required for IdentityBundle")
	}
	if d, ok := content.(*DSSEData); ok && (d == nil || len(d.Data) == 0 || d.PayloadType == "") {
		return nil, errors.New("DSSEData must have non-empty data and payload type")
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	payload := content.PreAuthEncoding()
	digest := sha256.Sum256(payload)

	req, err := cred.ToIdentityRequestV001(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create identity request: %w", err)
	}

	proof, err := opts.TransparencyLog.GetIdentityTransparencyLogEntry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get transparency log entry: %w", err)
	}
	if proof == nil {
		return nil, errors.New("transparency log returned nil proof")
	}

	if sig := req.GetPublicKey().GetSignature(); len(sig) > 0 {
		proof.Signature = &bundleV2.Signature{
			Signature: sig,
		}
	}

	bundle := &bundleV2.Bundle{
		MediaType: bundleV20MediaType,
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
				TransparencyLogProof: proof,
			},
		},
	}

	if d, ok := content.(*DSSEData); ok {
		bundle.Payload = &bundleV2.Payload{
			Payload:     d.Data,
			PayloadType: d.PayloadType,
		}
	}

	if opts.TrustedRoot != nil {
		iv, err := verify.NewIdentityVerifier(opts.TrustedRoot)
		if err != nil {
			return nil, err
		}
		b, err := verifyBundle.NewBundleV2(bundle)
		if err != nil {
			return nil, err
		}
		artifactOpts := verify.WithoutArtifactUnsafe()
		if bundle.GetPayload() == nil {
			artifactOpts = verify.WithArtifact(bytes.NewReader(payload))
		}
		var policyOpts []verify.PolicyOption
		if pk := req.GetPublicKey(); pk != nil {
			policyOpts = append(policyOpts, verify.WithKey())
			if len(pk.GetContext()) > 0 {
				policyOpts = append(policyOpts, verify.WithContext(pk.GetContext()))
			}
		} else {
			policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
		}
		policy := verify.NewPolicy(artifactOpts, policyOpts...)
		if _, err := iv.Verify(b, policy); err != nil {
			return nil, err
		}
	}

	return bundle, nil
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
