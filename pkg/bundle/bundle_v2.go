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

package bundle

import (
	"os"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"

	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

type BundleV2 struct { //nolint:revive
	*bundleV2.Bundle
}

var _ verify.SignedEntity = (*BundleV2)(nil)

func (b *BundleV2) Version() (string, error) {
	return "v2.0", nil
}

func (b *BundleV2) HasInclusionPromise() bool {
	return false
}

func (b *BundleV2) HasInclusionProof() bool {
	return b.VerificationMaterial != nil && b.VerificationMaterial.GetTlogProof() != nil
}

func (b *BundleV2) SignatureContent() (verify.SignatureContent, error) {
	switch content := b.Content.(type) {
	case *bundleV2.Bundle_MessageSignature:
		if content.MessageSignature == nil {
			return nil, ErrMissingVerificationMaterial
		}
		var sig []byte
		if content.MessageSignature.Signature != nil {
			sig = content.MessageSignature.Signature.Signature
		}
		return NewMessageSignature(
			nil,
			"",
			sig,
		), nil
	default:
		return nil, ErrUnimplemented
	}
}

func (b *BundleV2) Timestamps() ([][]byte, error) {
	return nil, ErrUnimplemented
}

func (b *BundleV2) TlogEntries() ([]*tlog.Entry, error) {
	return nil, ErrUnimplemented
}

func (b *BundleV2) VerificationContent() (verify.VerificationContent, error) {
	if b.VerificationMaterial == nil {
		return nil, ErrMissingVerificationMaterial
	}

	switch content := b.VerificationMaterial.GetContent().(type) {
	case *bundleV2.VerificationMaterial_TlogProof:
		if content.TlogProof == nil {
			return nil, ErrMissingVerificationMaterial
		}
		if pk := content.TlogProof.GetPublicKey(); pk != nil {
			return &PublicKey{
				hint: pk.Hint,
			}, nil
		}
		// If OIDC, it might not have a public key hint in the proof
		return nil, ErrUnimplemented
	case *bundleV2.VerificationMaterial_PublicKey:
		if content.PublicKey == nil || content.PublicKey.GetPublicKey() == nil {
			return nil, ErrMissingVerificationMaterial
		}
		return &PublicKey{
			hint: content.PublicKey.GetPublicKey().GetHint(),
		}, nil
	default:
		return nil, ErrMissingVerificationMaterial
	}
}

func (b *BundleV2) TlogProofs() ([]*bundleV2.TlogProof, error) {
	if b.VerificationMaterial == nil || b.VerificationMaterial.GetTlogProof() == nil {
		return nil, nil
	}
	return []*bundleV2.TlogProof{b.VerificationMaterial.GetTlogProof()}, nil
}

func LoadJSONFromPathV2(path string) (*BundleV2, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b bundleV2.Bundle
	err = protojson.Unmarshal(contents, &b)
	if err != nil {
		return nil, err
	}
	return &BundleV2{Bundle: &b}, nil
}
