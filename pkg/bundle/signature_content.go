package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type SignatureContent interface {
	EnsureFileMatchesDigest([]byte) error
	CheckSignature(signature.Verifier) error
	GetSignature() []byte
	HasEnvelope() (*Envelope, bool)
	HasMessage() (*MessageSignature, bool)
}

type MessageSignature struct {
	Digest          []byte
	DigestAlgorithm string
	Signature       []byte
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

func (e *Envelope) HasEnvelope() (*Envelope, bool) {
	return e, true
}

func (m *MessageSignature) HasEnvelope() (*Envelope, bool) {
	return nil, false
}

func (e *Envelope) HasMessage() (*MessageSignature, bool) {
	return nil, false
}

func (m *MessageSignature) HasMessage() (*MessageSignature, bool) {
	return m, true
}

func (m *MessageSignature) EnsureFileMatchesDigest(fileBytes []byte) error {
	if m.DigestAlgorithm != "SHA2_256" {
		return errors.New("Message has unsupported hash algorithm")
	}

	fileDigest := sha256.Sum256(fileBytes)
	if !bytes.Equal(m.Digest, fileDigest[:]) {
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

func (m *MessageSignature) CheckSignature(verifier signature.Verifier) error {
	opts := options.WithDigest(m.Digest)
	return verifier.VerifySignature(bytes.NewReader(m.Signature), bytes.NewReader([]byte{}), opts)
}

func (e *Envelope) CheckSignature(verifier signature.Verifier) error {
	pub, err := verifier.PublicKey()
	if err != nil {
		return err
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
	})
	if err != nil {
		return err
	}
	_, err = envVerifier.Verify(context.TODO(), e.Envelope)
	if err != nil {
		return err
	}
	return nil
}

func (m *MessageSignature) GetSignature() []byte {
	return m.Signature
}

func (e *Envelope) GetSignature() []byte {
	if len(e.Envelope.Signatures) == 0 {
		return []byte{}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(e.Envelope.Signatures[0].Sig)
	if err != nil {
		return []byte{}
	}

	return sigBytes
}
