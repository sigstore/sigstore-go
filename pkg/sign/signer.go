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
	"bytes"
	"context"
	"encoding/pem"
	"errors"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"

	verifyBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

type BundleOptions struct {
	// Optional certificate authority to get code signing certificate from.
	//
	// Typically a Fulcio instance; resulting bundle will contain a certificate
	// for its verification material content instead of a public key.
	CertificateAuthority CertificateAuthority
	// Optional options for certificate authority
	//
	// Some certificate authorities may require options to be set
	CertificateAuthorityOptions *CertificateAuthorityOptions
	// Optional list of timestamp authorities to contact for inclusion in bundle
	TimestampAuthorities []*TimestampAuthority
	// Optional list of Rekor instances to get transparency log entry from.
	//
	// Supports hashedrekord and dsse entry types.
	Rekors []*Rekor
	// Optional context for retrying network requests
	Context context.Context
	// Optional trusted root to verify signed bundle
	TrustedRoot root.TrustedMaterial
}

func Bundle(content Content, keypair Keypair, opts BundleOptions) (*protobundle.Bundle, error) {
	if keypair == nil {
		return nil, errors.New("Must provide a keypair for signing, like EphemeralKeypair")
	}

	if opts.Context == nil {
		opts.Context = context.TODO()
	}

	bundle := &protobundle.Bundle{MediaType: bundleV03MediaType}
	verifierOptions := []verify.VerifierOption{}

	// Sign content and add to bundle
	signature, digest, err := keypair.SignData(content.PreAuthEncoding())
	if err != nil {
		return nil, err
	}

	content.Bundle(bundle, signature, digest, keypair.GetHashAlgorithm())

	// Add verification information to bundle
	var verifierPEM []byte
	if opts.CertificateAuthority != nil {
		pubKeyBytes, err := opts.CertificateAuthority.GetCertificate(opts.Context, keypair, opts.CertificateAuthorityOptions)
		if err != nil {
			return nil, err
		}

		bundle.VerificationMaterial = &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: pubKeyBytes,
				},
			},
		}

		verifierPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: pubKeyBytes,
		})
	} else {
		bundle.VerificationMaterial = &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: string(keypair.GetHint()),
				},
			},
		}

		pubKeyStr, err := keypair.GetPublicKeyPem()
		if err != nil {
			return nil, err
		}
		verifierPEM = []byte(pubKeyStr)
	}

	for _, timestampAuthority := range opts.TimestampAuthorities {
		timestampBytes, err := timestampAuthority.GetTimestamp(opts.Context, signature)
		if err != nil {
			return nil, err
		}

		signedTimestamp := &protocommon.RFC3161SignedTimestamp{
			SignedTimestamp: timestampBytes,
		}

		if bundle.VerificationMaterial.TimestampVerificationData == nil {
			bundle.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{}
		}

		bundle.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps = append(bundle.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps, signedTimestamp)

		verifierOptions = append(verifierOptions, verify.WithSignedTimestamps(len(opts.TimestampAuthorities)))
	}

	if len(opts.Rekors) > 0 {
		for _, rekor := range opts.Rekors {
			err = rekor.GetTransparencyLogEntry(verifierPEM, bundle)
			if err != nil {
				return nil, err
			}
		}

		verifierOptions = append(verifierOptions, verify.WithTransparencyLog(len(opts.Rekors)), verify.WithIntegratedTimestamps(len(opts.Rekors)))
	}

	if opts.TrustedRoot != nil && len(verifierOptions) > 0 {
		sev, err := verify.NewSignedEntityVerifier(opts.TrustedRoot, verifierOptions...)
		if err != nil {
			return nil, err
		}

		protobundle, err := verifyBundle.NewProtobufBundle(bundle)
		if err != nil {
			return nil, err
		}

		artifactOpts := verify.WithArtifact(bytes.NewReader(content.PreAuthEncoding()))
		policy := verify.NewPolicy(artifactOpts, verify.WithoutIdentitiesUnsafe())
		_, err = sev.Verify(protobundle, policy)
		if err != nil {
			return nil, err
		}
	}

	return bundle, nil
}
