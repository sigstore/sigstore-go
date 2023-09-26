package verify

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/github/sigstore-go/pkg/root"
	"github.com/github/sigstore-go/pkg/tlog"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

var errNotImplemented = errors.New("not implemented")

type HasInclusionPromise interface {
	HasInclusionPromise() bool
}

type HasInclusionProof interface {
	HasInclusionProof() bool
}

type SignatureProvider interface {
	SignatureContent() (SignatureContent, error)
}

type SignedTimestampProvider interface {
	Timestamps() ([][]byte, error)
}

type TlogEntryProvider interface {
	TlogEntries() ([]*tlog.Entry, error)
}

type VerificationProvider interface {
	VerificationContent() (VerificationContent, error)
}

type SignedEntity interface {
	HasInclusionPromise
	HasInclusionProof
	SignatureProvider
	SignedTimestampProvider
	TlogEntryProvider
	VerificationProvider
}

type VerificationContent interface {
	CompareKey(any, root.TrustedMaterial) bool
	ValidAtTime(time.Time, root.TrustedMaterial) bool
	HasCertificate() (x509.Certificate, bool)
	HasPublicKey() (PublicKeyProvider, bool)
}

type SignatureContent interface {
	Signature() []byte
	EnvelopeContent() EnvelopeContent
	MessageSignatureContent() MessageSignatureContent
}

type PublicKeyProvider interface {
	Hint() string
}

type MessageSignatureContent interface {
	Digest() []byte
	DigestAlgorithm() string
	Signature() []byte
}

type EnvelopeContent interface {
	RawEnvelope() *dsse.Envelope
	Statement() (*in_toto.Statement, error)
}

// BaseSignedEntity is a helper struct that implements all the interfaces
// of SignedEntity. It can be embedded in a struct to implement the SignedEntity
// interface. This may be useful for testing, or for implementing a SignedEntity
// that only implements a subset of the interfaces.
type BaseSignedEntity struct{}

func (b *BaseSignedEntity) VerificationProvider() (VerificationContent, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) Envelope() (*dsse.Envelope, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) MessageSignature() (*protocommon.MessageSignature, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) Signature() ([]byte, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) Timestamps() ([][]byte, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) TlogEntries() ([]*tlog.Entry, error) {
	return nil, errNotImplemented
}
