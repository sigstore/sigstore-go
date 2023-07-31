package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type SignatureContent interface {
	EnsureFileMatchesDigest([]byte) error
	CheckSignature(signature.Verifier) error
	GetSignature() []byte
}

type MessageSignature struct {
	Digest          []byte
	DigestAlgorithm string
	Signature       []byte
}

type Envelope struct {
	*dsse.Envelope
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
