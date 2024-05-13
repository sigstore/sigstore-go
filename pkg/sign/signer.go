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
	"encoding/pem"
	"errors"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

type BundleOptions struct {
	// Optional Fulcio instance to get code signing certificate from.
	//
	// Resulting bundle will contain a certificate for its verification
	// material content, instead of a public key.
	Fulcio *Fulcio
	// Optional OIDC JWT to send to Fulcio; required if using Fulcio
	IDToken string
	// Optional list of timestamp authorities to contact for inclusion in bundle
	TimestampAuthorities []*TimestampAuthority
	// Optional list of Rekor instances to get transparency log entry from.
	//
	// Supports hashedrekord and dsse entry types
	Rekors []*Rekor
}

func Bundle(content Content, keypair Keypair, opts BundleOptions) (*protobundle.Bundle, error) {
	if keypair == nil {
		return nil, errors.New("Must provide a keypair for signing, like EphemeralKeypair")
	}

	if opts.Fulcio != nil && opts.IDToken == "" {
		return nil, errors.New("If opts.Fulcio is provided, must also supply opts.IDToken")
	}

	bundle := &protobundle.Bundle{MediaType: bundleV03MediaType}

	// Sign content and add to bundle
	signature, digest, err := keypair.SignData(content.PreAuthEncoding())
	if err != nil {
		return nil, err
	}

	content.Bundle(bundle, signature, digest, keypair.GetHashAlgorithm())

	// Add verification information to bundle
	var verifierPEM []byte
	if opts.Fulcio != nil && opts.IDToken != "" {
		pubKeyBytes, err := opts.Fulcio.GetCertificate(keypair, opts.IDToken)
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

		// TODO: do verification of Fulcio certificate
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
		timestampBytes, err := timestampAuthority.GetTimestamp(signature)
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
	}

	if len(opts.Rekors) > 0 {
		for _, rekor := range opts.Rekors {
			err = rekor.GetTransparencyLog(verifierPEM, bundle)
			if err != nil {
				return nil, err
			}
		}
	}

	return bundle, nil
}
