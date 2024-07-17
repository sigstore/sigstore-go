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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

type SubjectAlternativeNameMatcher struct {
	certificate.SubjectAlternativeName
	Regexp regexp.Regexp `json:"regexp,omitempty"`
}

type CertificateIdentity struct {
	SubjectAlternativeName SubjectAlternativeNameMatcher `json:"subjectAlternativeName"`
	certificate.Extensions
}

type CertificateIdentities []CertificateIdentity

type ErrSANTypeMismatch struct {
	expected string
	actual   string
}

func (e *ErrSANTypeMismatch) Error() string {
	return fmt.Sprintf("expected SAN type %s, got %s", e.expected, e.actual)
}

type ErrSANValueMismatch struct {
	expected string
	actual   string
}

func (e *ErrSANValueMismatch) Error() string {
	return fmt.Sprintf("expected SAN value \"%s\", got \"%s\"", e.expected, e.actual)
}

type ErrSANValueRegexMismatch struct {
	regex string
	value string
}

func (e *ErrSANValueRegexMismatch) Error() string {
	return fmt.Sprintf("expected SAN value to match regex \"%s\", got \"%s\"", e.regex, e.value)
}

type ErrNoMatchingCertificateIdentity struct {
	errors []error
}

func (e *ErrNoMatchingCertificateIdentity) Error() string {
	if len(e.errors) > 0 {
		return fmt.Sprintf("no matching CertificateIdentity found, last error: %v", e.errors[len(e.errors)-1])
	}
	return "no matching CertificateIdentity found"
}

func (e *ErrNoMatchingCertificateIdentity) Unwrap() []error {
	return e.errors
}

// NewSANMatcher provides an easier way to create a SubjectAlternativeNameMatcher.
// If the regexpStr fails to compile into a Regexp, an error is returned.
func NewSANMatcher(sanValue string, sanType string, regexpStr string) (SubjectAlternativeNameMatcher, error) {
	r, err := regexp.Compile(regexpStr)
	if err != nil {
		return SubjectAlternativeNameMatcher{}, err
	}

	return SubjectAlternativeNameMatcher{
		SubjectAlternativeName: certificate.SubjectAlternativeName{
			Value: sanValue,
			Type:  certificate.SubjectAlternativeNameType(sanType),
		},
		Regexp: *r}, nil
}

// The default Regexp json marshal is quite ugly, so we override it here.
func (s *SubjectAlternativeNameMatcher) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		certificate.SubjectAlternativeName
		Regexp string `json:"regexp,omitempty"`
	}{
		SubjectAlternativeName: s.SubjectAlternativeName,
		Regexp:                 s.Regexp.String(),
	})
}

// Verify checks if the actualCert matches the SANMatcher's Type, Value, and
// Regexp – if those values have been provided.
func (s SubjectAlternativeNameMatcher) Verify(actualCert certificate.Summary) error {
	if s.SubjectAlternativeName.Type != "" &&
		actualCert.SubjectAlternativeName.Type != s.SubjectAlternativeName.Type {
		return &ErrSANTypeMismatch{string(s.SubjectAlternativeName.Type), string(actualCert.SubjectAlternativeName.Type)}
	}

	if s.SubjectAlternativeName.Value != "" &&
		actualCert.SubjectAlternativeName.Value != s.SubjectAlternativeName.Value {
		return &ErrSANValueMismatch{string(s.SubjectAlternativeName.Value), string(actualCert.SubjectAlternativeName.Value)}
	}

	if s.Regexp.String() != "" &&
		!s.Regexp.MatchString(actualCert.SubjectAlternativeName.Value) {
		return &ErrSANValueRegexMismatch{string(s.Regexp.String()), string(actualCert.SubjectAlternativeName.Value)}
	}
	return nil
}

func NewCertificateIdentity(sanMatcher SubjectAlternativeNameMatcher, extensions certificate.Extensions) (CertificateIdentity, error) {
	if sanMatcher.SubjectAlternativeName.Value == "" && sanMatcher.Regexp.String() == "" {
		return CertificateIdentity{}, errors.New("when verifying a certificate identity, there must be subject alternative name criteria")
	}

	certID := CertificateIdentity{SubjectAlternativeName: sanMatcher, Extensions: extensions}

	if certID.Issuer == "" {
		return CertificateIdentity{}, errors.New("when verifying a certificate identity, the Issuer field can't be empty")
	}

	return certID, nil
}

// NewShortCertificateIdentity provides a more convenient way of initializing
// a CertificiateIdentity with a SAN and the Issuer OID extension. If you need
// to check more OID extensions, use NewCertificateIdentity instead.
func NewShortCertificateIdentity(issuer, sanValue, sanType, sanRegex string) (CertificateIdentity, error) {
	sanMatcher, err := NewSANMatcher(sanValue, sanType, sanRegex)
	if err != nil {
		return CertificateIdentity{}, err
	}

	return NewCertificateIdentity(sanMatcher, certificate.Extensions{Issuer: issuer})
}

// Verify verifies the CertificateIdentities, and if ANY of them match the cert,
// it returns the CertificateIdentity that matched. If none match, it returns an
// error.
func (i CertificateIdentities) Verify(cert certificate.Summary) (*CertificateIdentity, error) {
	multierr := &ErrNoMatchingCertificateIdentity{}
	var err error
	for _, ci := range i {
		if err = ci.Verify(cert); err == nil {
			return &ci, nil
		}
		multierr.errors = append(multierr.errors, err)
	}
	return nil, multierr
}

// Verify checks if the actualCert matches the CertificateIdentity's SAN and
// any of the provided OID extension values. Any empty values are ignored.
func (c CertificateIdentity) Verify(actualCert certificate.Summary) error {
	var err error
	if err = c.SubjectAlternativeName.Verify(actualCert); err != nil {
		return err
	}
	return certificate.CompareExtensions(c.Extensions, actualCert.Extensions)
}
