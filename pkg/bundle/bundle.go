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
	"google.golang.org/protobuf/encoding/protojson"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
)

const SigstoreBundleMediaType01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
const IntotoMediaType = "application/vnd.in-toto+json"

var ErrInvalidAttestation = errors.New("invalid attestation")
var ErrMissingEnvelope = fmt.Errorf("%w: missing envelope", ErrInvalidAttestation)
var ErrDecodingJSON = fmt.Errorf("%w: decoding json", ErrInvalidAttestation)
var ErrDecodingB64 = fmt.Errorf("%w: decoding base64", ErrInvalidAttestation)

type ProtobufBundle struct {
	protobundle.Bundle
}

func NewProtobufBundle(pbundle *protobundle.Bundle) *ProtobufBundle {
	return &ProtobufBundle{Bundle: *pbundle}
}

func LoadJSONFromPath(path string) (*ProtobufBundle, error) {
	var bundle ProtobufBundle

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
	return protojson.Marshal(&b.Bundle)
}

func (b *ProtobufBundle) UnmarshalJSON(data []byte) error {
	err := protojson.Unmarshal(data, &b.Bundle)
	if err != nil {
		return err
	}

	if b.Bundle.MediaType != SigstoreBundleMediaType01 {
		return ErrIncorrectMediaType
	}

	return nil
}

func (b *ProtobufBundle) CertificateChain() ([]*x509.Certificate, error) {
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
		return certificates, nil
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
		tlogEntries[i], _, _, err = tlog.ParseEntry(entry)
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

	switch content := b.VerificationMaterial.Content.(type) {
	case *protobundle.VerificationMaterial_PublicKey:
		if content.PublicKey == nil {
			return "", ErrMissingVerificationMaterial
		}
		return content.PublicKey.GetHint(), nil
	}
	return "", nil
}

func (b *ProtobufBundle) Envelope() (*dsse.Envelope, error) {
	switch content := b.Content.(type) {
	case *protobundle.Bundle_DsseEnvelope:
		return parseEnvelope(content.DsseEnvelope)
	}
	return nil, ErrMissingVerificationMaterial
}

func (b *ProtobufBundle) Statement() (*in_toto.Statement, error) {
	envelope, err := b.Envelope()
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

var ErrValidation = errors.New("validation error")
var ErrIncorrectMediaType = fmt.Errorf("%w: unsupported media type", ErrValidation)
var ErrMissingVerificationMaterial = fmt.Errorf("%w: missing verification material", ErrValidation)
var ErrUnimplemented = errors.New("unimplemented")

type ErrVerification struct {
	err error
}

func NewVerificationError(e error) ErrVerification {
	return ErrVerification{e}
}

func (e ErrVerification) Unwrap() error {
	return e.err
}

func (e ErrVerification) String() string {
	return fmt.Sprintf("verification error: %s", e.err.Error())
}

func (e ErrVerification) Error() string {
	return e.String()
}

func ErrValidationError(err error) error {
	return fmt.Errorf("%w: %s", ErrValidation, err)
}

func parseEnvelope(input *protodsse.Envelope) (*dsse.Envelope, error) {
	output := &dsse.Envelope{}
	output.Payload = base64.StdEncoding.EncodeToString([]byte(input.GetPayload()))
	output.PayloadType = string(input.GetPayloadType())
	output.Signatures = make([]dsse.Signature, len(input.GetSignatures()))
	for i, sig := range input.GetSignatures() {
		output.Signatures[i].KeyID = sig.GetKeyid()
		output.Signatures[i].Sig = base64.StdEncoding.EncodeToString(sig.GetSig())
	}
	return output, nil
}
