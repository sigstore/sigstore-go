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

package verify

import (
	"crypto/x509"
	"errors"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
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

type VersionProvider interface {
	Version() (string, error)
}

type SignedEntity interface {
	HasInclusionPromise
	HasInclusionProof
	SignatureProvider
	SignedTimestampProvider
	TlogEntryProvider
	VerificationProvider
	VersionProvider
}

type VerificationContent interface {
	CompareKey(any, root.TrustedMaterial) bool
	ValidAtTime(time.Time, root.TrustedMaterial) bool
	Certificate() *x509.Certificate
	Intermediates() []*x509.Certificate
	PublicKey() PublicKeyProvider
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

var _ SignedEntity = &BaseSignedEntity{}

func (b *BaseSignedEntity) HasInclusionPromise() bool {
	return false
}

func (b *BaseSignedEntity) HasInclusionProof() bool {
	return false
}

func (b *BaseSignedEntity) VerificationContent() (VerificationContent, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) SignatureContent() (SignatureContent, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) Timestamps() ([][]byte, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) TlogEntries() ([]*tlog.Entry, error) {
	return nil, errNotImplemented
}

func (b *BaseSignedEntity) Version() (string, error) {
	return "", errNotImplemented
}

// ===== Bundle v2 Interfaces =====

// VerifiableEntity represents a v2 bundle or entity that can be verified.
type VerifiableEntity interface {
	SignedTimestampProvider
	VersionProvider
	// HasTransparencyLogProof reports whether the entity's verification material contains a transparency log proof.
	HasTransparencyLogProof() bool
	// HasCertificate reports whether the entity's verification material contains an X.509 certificate.
	HasCertificate() bool
	// HasPublicKey reports whether the entity's verification material indicates a raw public key.
	HasPublicKey() bool
	// HasEnvelope reports whether the entity's content is an embedded DSSE envelope.
	HasEnvelope() bool
	// Signature returns the raw signature bytes from the entity's verification material.
	Signature() ([]byte, error)
	// Envelope returns the embedded DSSE envelope content when HasEnvelope is true.
	Envelope() (EnvelopeContent, error)
	// TransparencyLogProof returns the transparency log proof when HasTransparencyLogProof is true.
	TransparencyLogProof() (*bundleV2.TransparencyLogProof, error)
	// Certificate returns the leaf X.509 certificate and optional untrusted intermediates when HasCertificate is true.
	Certificate() (*x509.Certificate, []*x509.Certificate, error)
}

// BaseVerifiableEntity is a helper struct that implements all the interfaces
// of VerifiableEntity. It can be embedded in a struct to implement the VerifiableEntity
// interface.
type BaseVerifiableEntity struct{}

var _ VerifiableEntity = &BaseVerifiableEntity{}

func (b *BaseVerifiableEntity) HasTransparencyLogProof() bool {
	return false
}

func (b *BaseVerifiableEntity) HasCertificate() bool {
	return false
}

func (b *BaseVerifiableEntity) HasPublicKey() bool {
	return false
}

func (b *BaseVerifiableEntity) HasEnvelope() bool {
	return false
}

func (b *BaseVerifiableEntity) Signature() ([]byte, error) {
	return nil, errNotImplemented
}

func (b *BaseVerifiableEntity) Envelope() (EnvelopeContent, error) {
	return nil, errNotImplemented
}

func (b *BaseVerifiableEntity) Certificate() (*x509.Certificate, []*x509.Certificate, error) {
	return nil, nil, errNotImplemented
}

func (b *BaseVerifiableEntity) Timestamps() ([][]byte, error) {
	return nil, errNotImplemented
}

func (b *BaseVerifiableEntity) TransparencyLogProof() (*bundleV2.TransparencyLogProof, error) {
	return nil, errNotImplemented
}

func (b *BaseVerifiableEntity) Version() (string, error) {
	return "", errNotImplemented
}
