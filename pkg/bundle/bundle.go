// Copyright 2023 The Sigstore Authors.
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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const SigstoreBundleMediaType01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
const SigstoreBundleMediaType02 = "application/vnd.dev.sigstore.bundle+json;version=0.2"
const IntotoMediaType = "application/vnd.in-toto+json"

var ErrValidation = errors.New("validation error")
var ErrIncorrectMediaType = fmt.Errorf("%w: unsupported media type", ErrValidation)
var ErrMissingVerificationMaterial = fmt.Errorf("%w: missing verification material", ErrValidation)
var ErrUnimplemented = errors.New("unimplemented")
var ErrInvalidAttestation = fmt.Errorf("%w: invalid attestation", ErrValidation)
var ErrMissingEnvelope = fmt.Errorf("%w: missing envelope", ErrInvalidAttestation)
var ErrDecodingJSON = fmt.Errorf("%w: decoding json", ErrInvalidAttestation)
var ErrDecodingB64 = fmt.Errorf("%w: decoding base64", ErrInvalidAttestation)

func ErrValidationError(err error) error {
	return fmt.Errorf("%w: %w", ErrValidation, err)
}

type ProtobufBundle struct {
	*protobundle.Bundle
	hasInclusionPromise bool
	hasInclusionProof   bool
}

func NewProtobufBundle(pbundle *protobundle.Bundle) (*ProtobufBundle, error) {
	bundle := &ProtobufBundle{
		Bundle:              pbundle,
		hasInclusionPromise: false,
		hasInclusionProof:   false,
	}

	err := bundle.validate()
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func (b *ProtobufBundle) validate() error {
	entries, err := b.TlogEntries()
	if err != nil {
		return err
	}

	switch b.Bundle.MediaType {
	case SigstoreBundleMediaType01:
		if len(entries) > 0 && !b.hasInclusionPromise {
			return errors.New("inclusion promises missing in bundle (required for bundle v0.1)")
		}
	case SigstoreBundleMediaType02:
		if len(entries) > 0 && !b.hasInclusionProof {
			return errors.New("inclusion proof missing in bundle (required for bundle v0.2)")
		}
	default:
		return ErrIncorrectMediaType
	}

	return nil
}

func LoadJSONFromPath(path string) (*ProtobufBundle, error) {
	var bundle ProtobufBundle
	bundle.Bundle = new(protobundle.Bundle)

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = bundle.UnmarshalJSON(contents)
	if err != nil {
		return nil, err
	}

	return &bundle, nil
}

func (b *ProtobufBundle) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(b.Bundle)
}

func (b *ProtobufBundle) UnmarshalJSON(data []byte) error {
	b.Bundle = new(protobundle.Bundle)
	err := protojson.Unmarshal(data, b.Bundle)
	if err != nil {
		return err
	}

	err = b.validate()
	if err != nil {
		return err
	}

	return nil
}

func (b *ProtobufBundle) VerificationContent() (verify.VerificationContent, error) {
	if b.VerificationMaterial == nil {
		return nil, ErrMissingVerificationMaterial
	}

	switch content := b.VerificationMaterial.GetContent().(type) {
	case *protobundle.VerificationMaterial_X509CertificateChain:
		certs := content.X509CertificateChain.GetCertificates()
		certificates := make([]*x509.Certificate, len(certs))
		var err error
		for i, cert := range content.X509CertificateChain.GetCertificates() {
			certificates[i], err = x509.ParseCertificate(cert.RawBytes)
			if err != nil {
				return nil, ErrValidationError(err)
			}
		}
		if len(certificates) == 0 {
			return nil, ErrMissingVerificationMaterial
		}
		certChain := &CertificateChain{
			Certificates: certificates,
		}
		return certChain, nil
	case *protobundle.VerificationMaterial_PublicKey:
		pk := &PublicKey{
			hint: content.PublicKey.Hint,
		}
		return pk, nil

	default:
		return nil, ErrMissingVerificationMaterial
	}
}

func (b *ProtobufBundle) HasInclusionPromise() bool {
	return b.hasInclusionPromise
}

func (b *ProtobufBundle) HasInclusionProof() bool {
	return b.hasInclusionProof
}

func (b *ProtobufBundle) TlogEntries() ([]*tlog.Entry, error) {
	if b.VerificationMaterial == nil {
		return nil, nil
	}

	tlogEntries := make([]*tlog.Entry, len(b.VerificationMaterial.TlogEntries))
	var err error
	for i, entry := range b.VerificationMaterial.TlogEntries {
		tlogEntries[i], err = tlog.ParseEntry(entry)
		if err != nil {
			return nil, ErrValidationError(err)
		}

		if tlogEntries[i].HasInclusionPromise() {
			b.hasInclusionPromise = true
		}
		if tlogEntries[i].HasInclusionProof() {
			b.hasInclusionProof = true
		}
	}

	return tlogEntries, nil
}

func (b *ProtobufBundle) SignatureContent() (verify.SignatureContent, error) {
	switch content := b.Bundle.Content.(type) { //nolint:gocritic
	case *protobundle.Bundle_DsseEnvelope:
		envelope, err := parseEnvelope(content.DsseEnvelope)
		if err != nil {
			return nil, err
		}
		return envelope, nil
	case *protobundle.Bundle_MessageSignature:
		return NewMessageSignature(
			content.MessageSignature.MessageDigest.Digest,
			protocommon.HashAlgorithm_name[int32(content.MessageSignature.MessageDigest.Algorithm)],
			content.MessageSignature.Signature,
		), nil
	}
	return nil, ErrMissingVerificationMaterial
}

func (b *ProtobufBundle) Envelope() (*Envelope, error) {
	switch content := b.Bundle.Content.(type) { //nolint:gocritic
	case *protobundle.Bundle_DsseEnvelope:
		envelope, err := parseEnvelope(content.DsseEnvelope)
		if err != nil {
			return nil, err
		}
		return envelope, nil
	}
	return nil, ErrMissingVerificationMaterial
}

func (b *ProtobufBundle) Timestamps() ([][]byte, error) {
	if b.VerificationMaterial == nil {
		return nil, ErrMissingVerificationMaterial
	}

	signedTimestamps := make([][]byte, 0)

	if b.VerificationMaterial.TimestampVerificationData == nil {
		return signedTimestamps, nil
	}

	for _, timestamp := range b.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps {
		signedTimestamps = append(signedTimestamps, timestamp.SignedTimestamp)
	}

	return signedTimestamps, nil
}

func (b *ProtobufBundle) MinVersion(version string) bool {
	mediaTypeParts := strings.Split(b.Bundle.MediaType, "version=")
	if len(mediaTypeParts) < 2 {
		return false
	}

	return semver.Compare("v"+mediaTypeParts[1], "v"+version) >= 0
}

func parseEnvelope(input *protodsse.Envelope) (*Envelope, error) {
	output := &dsse.Envelope{}
	output.Payload = base64.StdEncoding.EncodeToString([]byte(input.GetPayload()))
	output.PayloadType = string(input.GetPayloadType())
	output.Signatures = make([]dsse.Signature, len(input.GetSignatures()))
	for i, sig := range input.GetSignatures() {
		output.Signatures[i].KeyID = sig.GetKeyid()
		output.Signatures[i].Sig = base64.StdEncoding.EncodeToString(sig.GetSig())
	}
	return &Envelope{Envelope: output}, nil
}
