package verifier

import (
	"crypto/x509"
	"errors"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

var errNotImplemented = errors.New("not implemented")

type SignatureProvider interface {
	Signature() ([]byte, error)
}

type KeyIDProvider interface {
	KeyID() (string, error)
}

type CertificateProvider interface {
	CertificateChain() ([]*x509.Certificate, error)
}

type ContentProvider interface {
	Content() (bundle.Content, error)
}

type SignedTimestampProvider interface {
	Timestamps() ([][]byte, error)
}

type TlogEntryProvider interface {
	TlogEntries() ([]*tlog.Entry, error)
}

type Verifier interface {
	Verify(SignedEntity) error
}

type SignedEntity interface {
	CertificateProvider
	ContentProvider
	KeyIDProvider
	SignedTimestampProvider
	TlogEntryProvider
}

func Verify(entity SignedEntity, verifiers ...Verifier) error {
	for _, verifier := range verifiers {
		if err := verifier.Verify(entity); err != nil {
			return NewVerificationError(err)
		}
	}
	return nil
}

// BaseSignedEntity is a helper struct that implements all the interfaces
// of SignedEntity. It can be embedded in a struct to implement the SignedEntity
// interface. This may be useful for testing, or for implementing a SignedEntity
// that only implements a subset of the interfaces.
type BaseSignedEntity struct{}

func (b *BaseSignedEntity) CertificateChain() ([]*x509.Certificate, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) Envelope() (*dsse.Envelope, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) MessageSignature() (*protocommon.MessageSignature, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) KeyID() (string, error) {
	return "", errNotImplemented
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
