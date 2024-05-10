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
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

func Bundle(content Content, keypair Keypair, fulcio *Fulcio, idToken string, timestampAuthority *TimestampAuthority) (*protobundle.Bundle, error) {
	// See if keypair was provided
	if keypair == nil {
		var err error
		ephemeralKeypair, err := NewEphemeralKeypair(nil)
		if err != nil {
			return nil, err
		}
		keypair = ephemeralKeypair
	}

	bundle := &protobundle.Bundle{MediaType: bundleV03MediaType}

	// Sign content and add to bundle
	signature, digest, err := keypair.SignData(content.PreAuthEncoding())
	if err != nil {
		return nil, err
	}

	content.Bundle(bundle, signature, digest, keypair.GetHashAlgorithm())

	// Add verification information to bundle
	if fulcio != nil {
		certBytes, err := fulcio.GetCertificate(keypair, idToken)
		if err != nil {
			return nil, err
		}

		bundle.VerificationMaterial = &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: certBytes,
				},
			},
		}
	} else {
		bundle.VerificationMaterial = &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: string(keypair.GetHint()),
				},
			},
		}
	}

	if timestampAuthority != nil {
		timestampBytes, err := timestampAuthority.GetTimestamp(signature)
		if err != nil {
			return nil, err
		}

		signedTimestamp := &protocommon.RFC3161SignedTimestamp{
			SignedTimestamp: timestampBytes,
		}

		tsVerificationData := &protobundle.TimestampVerificationData{}
		tsVerificationData.Rfc3161Timestamps = append(tsVerificationData.Rfc3161Timestamps, signedTimestamp)

		bundle.VerificationMaterial.TimestampVerificationData = tsVerificationData
	}

	return bundle, nil
}
