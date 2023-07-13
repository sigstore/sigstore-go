package bundle

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/github/sigstore-verifier/pkg/tlog"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

const SigstoreBundleMediaType01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
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
}

func NewProtobufBundle(pbundle *protobundle.Bundle) (*ProtobufBundle, error) {
	if pbundle.MediaType != SigstoreBundleMediaType01 {
		return nil, ErrIncorrectMediaType
	}
	// TODO: Add support for bundle v0.2
	return &ProtobufBundle{Bundle: pbundle}, nil
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

	if b.Bundle.MediaType != SigstoreBundleMediaType01 {
		return ErrIncorrectMediaType
	}

	return nil
}

func (b *ProtobufBundle) VerificationContent() (VerificationContent, error) {
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
		// TODO - how do we get public key bytes from identifier?
		hint := content.PublicKey.Hint
		_ = hint

		pk := &PublicKey{
			PublicKey: nil,
		}
		return pk, nil

	default:
		return nil, ErrMissingVerificationMaterial
	}
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
	}

	return tlogEntries, nil
}

func (b *ProtobufBundle) KeyID() (string, error) {
	if b.VerificationMaterial == nil {
		return "", ErrMissingVerificationMaterial
	}

	switch content := b.VerificationMaterial.Content.(type) { //nolint:gocritic
	case *protobundle.VerificationMaterial_PublicKey:
		if content.PublicKey == nil {
			return "", ErrMissingVerificationMaterial
		}
		return content.PublicKey.GetHint(), nil
	}
	return "", nil
}

func (b *ProtobufBundle) SignatureContent() (SignatureContent, error) {
	switch content := b.Bundle.Content.(type) { //nolint:gocritic
	case *protobundle.Bundle_DsseEnvelope:
		envelope, err := parseEnvelope(content.DsseEnvelope)
		if err != nil {
			return nil, err
		}
		return envelope, nil
	case *protobundle.Bundle_MessageSignature:
		messageSignature := MessageSignature{
			Digest:          content.MessageSignature.MessageDigest.Digest,
			DigestAlgorithm: protocommon.HashAlgorithm_name[int32(content.MessageSignature.MessageDigest.Algorithm)],
			Signature:       content.MessageSignature.Signature,
		}
		return &messageSignature, nil
	}
	return nil, ErrMissingVerificationMaterial
}

func (b *ProtobufBundle) dsseEnvelope() (*dsse.Envelope, error) {
	switch content := b.Bundle.Content.(type) { //nolint:gocritic
	case *protobundle.Bundle_DsseEnvelope:
		envelope, err := parseEnvelope(content.DsseEnvelope)
		if err != nil {
			return nil, err
		}
		return envelope.Envelope, nil
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

func (b *ProtobufBundle) Statement() (*in_toto.Statement, error) {
	envelope, err := b.dsseEnvelope()
	if err != nil {
		return nil, err
	}

	if envelope.PayloadType != IntotoMediaType {
		return nil, ErrIncorrectMediaType
	}

	var statement *in_toto.Statement
	raw, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, ErrDecodingB64
	}
	err = json.Unmarshal(raw, &statement)
	if err != nil {
		return nil, ErrDecodingJSON
	}
	return statement, nil
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
