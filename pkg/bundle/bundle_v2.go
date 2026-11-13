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
	"encoding/base64"
	"fmt"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// BundleV2 wraps a v2 protobuf bundle and implements verify.VerifiableEntity.
type BundleV2 struct { //nolint:revive
	*bundleV2.Bundle
}

var _ verify.VerifiableEntity = (*BundleV2)(nil)

// NewBundleV2 validates and wraps a v2 protobuf bundle.
func NewBundleV2(pbundle *bundleV2.Bundle) (*BundleV2, error) {
	if pbundle == nil {
		return nil, ErrEmptyBundle
	}
	b := &BundleV2{Bundle: pbundle}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *BundleV2) validate() error {
	if _, err := b.Version(); err != nil {
		return fmt.Errorf("error getting bundle version: %w", err)
	}
	if b.Payload != nil && (len(b.Payload.Payload) == 0 || b.Payload.PayloadType == "") {
		return ErrMissingEnvelope
	}
	if b.VerificationMaterial == nil || b.VerificationMaterial.Content == nil {
		return ErrMissingVerificationMaterial
	}
	switch content := b.VerificationMaterial.Content.(type) {
	case *bundleV2.VerificationMaterial_TransparencyLogProof:
		if content.TransparencyLogProof == nil || len(content.TransparencyLogProof.Proof) == 0 {
			return ErrMissingVerificationMaterial
		}
		if content.TransparencyLogProof.Signature != nil && len(content.TransparencyLogProof.Signature.Signature) == 0 {
			return ErrMissingVerificationMaterial
		}
	case *bundleV2.VerificationMaterial_PublicKey:
		if content.PublicKey == nil || len(content.PublicKey.GetSignature().GetSignature()) == 0 {
			return ErrMissingVerificationMaterial
		}
	case *bundleV2.VerificationMaterial_Certificate:
		if content.Certificate == nil || len(content.Certificate.GetCertificate().GetRawBytes()) == 0 || len(content.Certificate.GetTimestamps().GetRfc3161Timestamps()) == 0 || len(content.Certificate.GetSignature().GetSignature()) == 0 {
			return ErrMissingVerificationMaterial
		}
	default:
		return ErrMissingVerificationMaterial
	}
	return nil
}

// MarshalJSON serializes the v2 bundle to protobuf JSON.
func (b *BundleV2) MarshalJSON() ([]byte, error) {
	if b.Bundle == nil {
		return nil, ErrEmptyBundle
	}
	return protojson.Marshal(b.Bundle)
}

// UnmarshalJSON deserializes and validates a v2 bundle from protobuf JSON.
func (b *BundleV2) UnmarshalJSON(data []byte) error {
	b.Bundle = new(bundleV2.Bundle)
	if err := protojson.Unmarshal(data, b.Bundle); err != nil {
		return err
	}
	return b.validate()
}

// HasTransparencyLogProof reports whether the bundle's verification material contains a transparency log proof.
func (b *BundleV2) HasTransparencyLogProof() bool {
	return b.Bundle != nil && b.VerificationMaterial.GetTransparencyLogProof() != nil
}

// HasCertificate reports whether the bundle's verification material contains an X.509 certificate.
func (b *BundleV2) HasCertificate() bool {
	return b.Bundle != nil && b.VerificationMaterial.GetCertificate() != nil
}

// HasPublicKey reports whether the bundle's verification material indicates a raw public key.
func (b *BundleV2) HasPublicKey() bool {
	return b.Bundle != nil && b.VerificationMaterial.GetPublicKey() != nil
}

// HasEnvelope reports whether the bundle contains an embedded DSSE payload.
func (b *BundleV2) HasEnvelope() bool {
	return b.Bundle != nil && b.GetPayload() != nil
}

// Version returns the bundle version string (e.g. "v2.0").
func (b *BundleV2) Version() (string, error) {
	if b.Bundle == nil {
		return "", ErrEmptyBundle
	}
	version, err := getBundleVersion(b.MediaType)
	if err != nil {
		return "", err
	}
	if version != "v2.0" {
		return "", fmt.Errorf("%w: bundle version %s is not a supported v2 bundle", ErrUnsupportedMediaType, version)
	}
	return version, nil
}

// Signature returns the raw signature bytes from the bundle's verification material.
func (b *BundleV2) Signature() ([]byte, error) {
	switch {
	case b.HasTransparencyLogProof():
		return b.VerificationMaterial.GetTransparencyLogProof().GetSignature().GetSignature(), nil
	case b.HasCertificate():
		return b.VerificationMaterial.GetCertificate().GetSignature().GetSignature(), nil
	case b.HasPublicKey():
		return b.VerificationMaterial.GetPublicKey().GetSignature().GetSignature(), nil
	default:
		return nil, ErrMissingVerificationMaterial
	}
}

// Envelope returns the embedded DSSE envelope content when HasEnvelope is true.
func (b *BundleV2) Envelope() (verify.EnvelopeContent, error) {
	if !b.HasEnvelope() {
		return nil, ErrMissingEnvelope
	}
	payload := b.GetPayload()
	if len(payload.Payload) == 0 || payload.PayloadType == "" {
		return nil, ErrMissingEnvelope
	}
	env := &dsse.Envelope{
		PayloadType: payload.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload.Payload),
	}
	if sig, _ := b.Signature(); len(sig) > 0 {
		env.Signatures = []dsse.Signature{
			{
				Sig: base64.StdEncoding.EncodeToString(sig),
			},
		}
	}
	return &Envelope{Envelope: env}, nil
}

// Timestamps returns the RFC 3161 signed timestamps from the bundle's verification material.
func (b *BundleV2) Timestamps() ([][]byte, error) {
	if b.Bundle == nil || b.VerificationMaterial == nil {
		return nil, ErrMissingVerificationMaterial
	}
	var tsData *bundleV2.TimestampVerificationData
	switch {
	case b.HasCertificate():
		tsData = b.VerificationMaterial.GetCertificate().GetTimestamps()
	case b.HasPublicKey():
		tsData = b.VerificationMaterial.GetPublicKey().GetTimestamps()
	}
	signedTimestamps := make([][]byte, 0)
	for _, ts := range tsData.GetRfc3161Timestamps() {
		if ts != nil {
			signedTimestamps = append(signedTimestamps, ts.SignedTimestamp)
		}
	}
	return signedTimestamps, nil
}

// Certificate returns the leaf X.509 certificate and optional intermediates when HasCertificate is true.
func (b *BundleV2) Certificate() (*x509.Certificate, []*x509.Certificate, error) {
	if !b.HasCertificate() {
		return nil, nil, ErrMissingVerificationMaterial
	}
	certContent := b.VerificationMaterial.GetCertificate()
	if certContent.Certificate == nil || certContent.Certificate.RawBytes == nil {
		return nil, nil, ErrMissingVerificationMaterial
	}
	parsedCert, err := x509.ParseCertificate(certContent.Certificate.RawBytes)
	if err != nil {
		return nil, nil, ErrValidationError(err)
	}
	intermediates, err := parseIntermediateCertificates(certContent.GetIntermediates().GetCertificates())
	if err != nil {
		return nil, nil, err
	}
	return parsedCert, intermediates, nil
}

// TransparencyLogProof returns the transparency log proof when HasTransparencyLogProof is true.
func (b *BundleV2) TransparencyLogProof() (*bundleV2.TransparencyLogProof, error) {
	if !b.HasTransparencyLogProof() {
		return nil, ErrMissingVerificationMaterial
	}
	return b.VerificationMaterial.GetTransparencyLogProof(), nil
}

// LoadJSONFromPathV2 loads a v2 bundle from a JSON file at the given path.
func LoadJSONFromPathV2(path string) (*BundleV2, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b BundleV2
	if err := b.UnmarshalJSON(contents); err != nil {
		return nil, err
	}
	return &b, nil
}
