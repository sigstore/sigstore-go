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
	"crypto/x509"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// BundleV2 wraps a v2 protobuf bundle and implements verify.VerifiableEntity.
type BundleV2 struct { //nolint:revive
	*bundleV2.Bundle
}

var _ verify.VerifiableEntity = (*BundleV2)(nil)

// NewBundleV2 validates and wraps a v2 protobuf bundle.
func NewBundleV2(_ *bundleV2.Bundle) (*BundleV2, error) {
	return nil, ErrUnimplemented
}

// MarshalJSON serializes the v2 bundle to protobuf JSON.
func (b *BundleV2) MarshalJSON() ([]byte, error) {
	return nil, ErrUnimplemented
}

// UnmarshalJSON deserializes and validates a v2 bundle from protobuf JSON.
func (b *BundleV2) UnmarshalJSON(_ []byte) error {
	return ErrUnimplemented
}

// HasTransparencyLogProof reports whether the bundle's verification material contains a transparency log proof.
func (b *BundleV2) HasTransparencyLogProof() bool {
	return false
}

// HasCertificate reports whether the bundle's verification material contains an X.509 certificate.
func (b *BundleV2) HasCertificate() bool {
	return false
}

// HasPublicKey reports whether the bundle's verification material indicates a raw public key.
func (b *BundleV2) HasPublicKey() bool {
	return false
}

// HasEnvelope reports whether the bundle contains an embedded DSSE payload.
func (b *BundleV2) HasEnvelope() bool {
	return false
}

// Version returns the bundle version string (e.g. "v2.0").
func (b *BundleV2) Version() (string, error) {
	return "", ErrUnimplemented
}

// Signature returns the raw signature bytes from the bundle's verification material.
func (b *BundleV2) Signature() ([]byte, error) {
	return nil, ErrUnimplemented
}

// Envelope returns the embedded DSSE envelope content when HasEnvelope is true.
func (b *BundleV2) Envelope() (verify.EnvelopeContent, error) {
	return nil, ErrUnimplemented
}

// Timestamps returns the RFC 3161 signed timestamps from the bundle's verification material.
func (b *BundleV2) Timestamps() ([][]byte, error) {
	return nil, ErrUnimplemented
}

// Certificate returns the leaf X.509 certificate and optional intermediates when HasCertificate is true.
func (b *BundleV2) Certificate() (*x509.Certificate, []*x509.Certificate, error) {
	return nil, nil, ErrUnimplemented
}

// TransparencyLogProof returns the transparency log proof when HasTransparencyLogProof is true.
func (b *BundleV2) TransparencyLogProof() (*bundleV2.TransparencyLogProof, error) {
	return nil, ErrUnimplemented
}

// LoadJSONFromPathV2 loads a v2 bundle from a JSON file at the given path.
func LoadJSONFromPathV2(_ string) (*BundleV2, error) {
	return nil, ErrUnimplemented
}
