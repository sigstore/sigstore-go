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

package verify

import (
	"errors"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type IdentityVerificationResult struct {
	Verified         bool
	Timestamps       []time.Time
	Statement        *in_toto.Statement
	VerifiedIdentity *CertificateIdentity
}

// IdentityVerifier verifies transparent signatures logged with an OIDC identity token
// or a public key credential.
type IdentityVerifier struct {
	trustedMaterial root.TrustedMaterial
}

type IdentityVerifierOption func(*IdentityVerifier) error

func NewIdentityVerifier(trustedMaterial root.TrustedMaterial, options ...IdentityVerifierOption) (*IdentityVerifier, error) {
	if trustedMaterial == nil {
		return nil, errors.New("trustedMaterial must not be nil")
	}
	v := &IdentityVerifier{trustedMaterial: trustedMaterial}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *IdentityVerifier) Verify(_ VerifiableEntity, _ PolicyBuilder) (*IdentityVerificationResult, error) {
	return nil, errNotImplemented
}

// PKIVerifier verifies PKI-based signatures backed by a certificate authority and
// RFC 3161 timestamp authority without a transparency log.
type PKIVerifier struct {
	trustedMaterial          root.TrustedMaterial
	signedTimestampThreshold int
}

type PKIVerifierOption func(*PKIVerifier) error

// WithPKISignedTimestamps configures PKIVerifier to require at least threshold
// RFC 3161 signed timestamps. Defaults to 1 if not specified.
func WithPKISignedTimestamps(threshold int) PKIVerifierOption {
	return func(v *PKIVerifier) error {
		if threshold < 1 {
			return errors.New("signed timestamp threshold must be at least 1")
		}
		v.signedTimestampThreshold = threshold
		return nil
	}
}

func NewPKIVerifier(trustedMaterial root.TrustedMaterial, options ...PKIVerifierOption) (*PKIVerifier, error) {
	if trustedMaterial == nil {
		return nil, errors.New("trustedMaterial must not be nil")
	}
	v := &PKIVerifier{
		trustedMaterial:          trustedMaterial,
		signedTimestampThreshold: 1,
	}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *PKIVerifier) Verify(_ VerifiableEntity, _ PolicyBuilder) (*IdentityVerificationResult, error) {
	return nil, errNotImplemented
}

// KeyVerifier verifies managed key signatures without a transparency log, with
// optional RFC 3161 timestamp verification.
type KeyVerifier struct {
	trustedMaterial          root.TrustedMaterial
	signedTimestampThreshold int
}

type KeyVerifierOption func(*KeyVerifier) error

// WithKeySignedTimestamps configures KeyVerifier to require at least threshold
// RFC 3161 signed timestamps and verify that the signing key was valid at those timestamps.
func WithKeySignedTimestamps(threshold int) KeyVerifierOption {
	return func(v *KeyVerifier) error {
		if threshold < 1 {
			return errors.New("signed timestamp threshold must be at least 1")
		}
		v.signedTimestampThreshold = threshold
		return nil
	}
}

func NewKeyVerifier(trustedMaterial root.TrustedMaterial, options ...KeyVerifierOption) (*KeyVerifier, error) {
	if trustedMaterial == nil {
		return nil, errors.New("trustedMaterial must not be nil")
	}
	v := &KeyVerifier{trustedMaterial: trustedMaterial}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *KeyVerifier) Verify(_ VerifiableEntity, _ PolicyBuilder) (*IdentityVerificationResult, error) {
	return nil, errNotImplemented
}
