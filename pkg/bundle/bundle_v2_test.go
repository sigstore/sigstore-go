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
	"path/filepath"
	"testing"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestBundleV2_InterfaceMethods(t *testing.T) {
	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TlogProof{
				TlogProof: &bundleV2.TlogProof{
					Proof: []byte("proof"),
					PublicKey: &pbcommon.PublicKeyIdentifier{
						Hint: "hint",
					},
				},
			},
		},
		Content: &bundleV2.Bundle_MessageSignature{
			MessageSignature: &bundleV2.MessageSignature{
				Signature: &bundleV2.Signature{
					Signature: []byte("sig"),
				},
			},
		},
	}

	b := &BundleV2{Bundle: pb}

	ver, err := b.Version()
	assert.NoError(t, err)
	assert.Equal(t, "v2.0", ver)

	assert.False(t, b.HasInclusionPromise())
	assert.True(t, b.HasInclusionProof())

	sigContent, err := b.SignatureContent()
	assert.NoError(t, err)
	assert.NotNil(t, sigContent)
	msgSig := sigContent.MessageSignatureContent()
	assert.NotNil(t, msgSig)
	assert.Equal(t, []byte("sig"), msgSig.Signature())

	verContent, err := b.VerificationContent()
	assert.NoError(t, err)
	assert.NotNil(t, verContent)
	assert.NotNil(t, verContent.PublicKey())
	assert.Equal(t, "hint", verContent.PublicKey().Hint())

	tlogProofs, err := b.TlogProofs()
	assert.NoError(t, err)
	assert.Len(t, tlogProofs, 1)
	assert.Equal(t, []byte("proof"), tlogProofs[0].Proof)

	_, err = b.Timestamps()
	assert.ErrorIs(t, err, ErrUnimplemented)

	_, err = b.TlogEntries()
	assert.ErrorIs(t, err, ErrUnimplemented)
}

func TestBundleV2_UnmarshalAndInterface(t *testing.T) {
	// Let's create a minimal bundle JSON matching BundleV2
	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TlogProof{
				TlogProof: &bundleV2.TlogProof{
					Proof: []byte("proof123"),
				},
			},
		},
		Content: &bundleV2.Bundle_MessageSignature{
			MessageSignature: &bundleV2.MessageSignature{
				Signature: &bundleV2.Signature{
					Signature: []byte("sig456"),
				},
			},
		},
	}

	bytes, err := protojson.Marshal(pb)
	assert.NoError(t, err)

	var parsed bundleV2.Bundle
	err = protojson.Unmarshal(bytes, &parsed)
	assert.NoError(t, err)

	b := &BundleV2{Bundle: &parsed}

	ver, err := b.Version()
	assert.NoError(t, err)
	assert.Equal(t, "v2.0", ver)

	tlogProofs, err := b.TlogProofs()
	assert.NoError(t, err)
	assert.Len(t, tlogProofs, 1)
	assert.Equal(t, []byte("proof123"), tlogProofs[0].Proof)
}

func TestLoadJSONFromPathV2(t *testing.T) {
	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
	}
	bytes, err := protojson.Marshal(pb)
	assert.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "bundle.json")
	err = os.WriteFile(tmpFile, bytes, 0600)
	assert.NoError(t, err)

	b, err := LoadJSONFromPathV2(tmpFile)
	assert.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, "application/vnd.dev.sigstore.bundle.v2.0+json", b.MediaType)
}
