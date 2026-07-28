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

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

type IdentityBundleOptions struct {
	TransparencyLogs []IdentityTransparencyLog
	Context          context.Context
}

// IdentityBundle creates a Bundle V2 using the transparent signature flow.
func IdentityBundle(content Content, cred IdentityCredential, opts IdentityBundleOptions) (*bundleV2.Bundle, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}

	payload := content.PreAuthEncoding()

	digest := sha256.Sum256(payload)

	var proof *bundleV2.TlogProof
	var err error
	if len(opts.TransparencyLogs) > 0 {
		// Bundle V2 currently supports a single TlogProof in its verification material.
		proof, err = opts.TransparencyLogs[0].GetIdentityTransparencyLogEntry(ctx, cred, digest[:])
		if err != nil {
			return nil, fmt.Errorf("failed to get transparency log entry: %w", err)
		}
	} else {
		return nil, fmt.Errorf("at least one transparency log is required for IdentityBundle")
	}

	artifactSigBytes, err := cred.ArtifactSignature(ctx, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate artifact signature: %w", err)
	}

	var pbSig *bundleV2.Signature
	if artifactSigBytes != nil {
		pbSig = &bundleV2.Signature{
			Signature: artifactSigBytes,
		}

		// If we have an artifact signature, we also have a public key hint we should inject into the TlogProof
		if pkc, ok := cred.(*PublicKeyCredential); ok {
			proof.PublicKey = &pbcommon.PublicKeyIdentifier{
				Hint: string(pkc.Keypair.GetHint()),
			}
		}
	}

	bundle := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TlogProof{
				TlogProof: proof,
			},
		},
	}

	if pbSig != nil {
		bundle.Content = &bundleV2.Bundle_MessageSignature{
			MessageSignature: &bundleV2.MessageSignature{
				Signature: pbSig,
			},
		}
	}

	return bundle, nil
}
