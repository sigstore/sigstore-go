package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/github/sigstore-verifier/pkg/verify"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type MessageSignature struct {
	digest          []byte
	digestAlgorithm string
	signature       []byte
}

func (m *MessageSignature) Digest() []byte {
	return m.digest
}

func (m *MessageSignature) DigestAlgorithm() string {
	return m.digestAlgorithm
}

type Envelope struct {
	*dsse.Envelope
}

func (e *Envelope) Statement() (*in_toto.Statement, error) {
	if e.PayloadType != IntotoMediaType {
		return nil, ErrIncorrectMediaType
	}

	var statement *in_toto.Statement
	raw, err := e.DecodeB64Payload()
	if err != nil {
		return nil, ErrDecodingB64
	}
	err = json.Unmarshal(raw, &statement)
	if err != nil {
		return nil, ErrDecodingJSON
	}
	return statement, nil
}

func (e *Envelope) EnvelopeContent() verify.EnvelopeContent {
	return e
}

func (e *Envelope) RawEnvelope() *dsse.Envelope {
	return e.Envelope
}

func (m *MessageSignature) EnvelopeContent() verify.EnvelopeContent {
	return nil
}

func (e *Envelope) MessageSignatureContent() verify.MessageSignatureContent {
	return nil
}

func (m *MessageSignature) MessageSignatureContent() verify.MessageSignatureContent {
	return m
}

func (m *MessageSignature) EnsureFileMatchesDigest(fileBytes []byte) error {
	if m.digestAlgorithm != "SHA2_256" {
		return errors.New("Message has unsupported hash algorithm")
	}

	fileDigest := sha256.Sum256(fileBytes)
	if !bytes.Equal(m.digest, fileDigest[:]) {
		return errors.New("Message signature does not match supplied file")
	}
	return nil
}

func (e *Envelope) EnsureFileMatchesDigest(fileBytes []byte) error {
	if e.Payload != base64.StdEncoding.EncodeToString(fileBytes) {
		return errors.New("Envelope payload does not match supplied file")
	}
	return nil
}

func (m *MessageSignature) Signature() []byte {
	return m.signature
}

func (e *Envelope) Signature() []byte {
	if len(e.Envelope.Signatures) == 0 {
		return []byte{}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(e.Envelope.Signatures[0].Sig)
	if err != nil {
		return []byte{}
	}

	return sigBytes
}
