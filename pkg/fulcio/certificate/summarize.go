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

package certificate

import (
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
)

// Normally, we would make this an int and use iota to assign values. However,
// our goal is to allow users to evaluate this data with a policy engine.
// Defining the types as strings should make it easier for end users to discover
// and use the NameType field.
type SubjectAlternativeNameType string

const (
	SubjectAlternativeNameTypeUnspecified SubjectAlternativeNameType = "Unspecified"
	SubjectAlternativeNameTypeEmail       SubjectAlternativeNameType = "Email"
	SubjectAlternativeNameTypeURI         SubjectAlternativeNameType = "URI"
	SubjectAlternativeNameTypeOther       SubjectAlternativeNameType = "Other"
)

type SubjectAlternativeName struct {
	Type  SubjectAlternativeNameType `json:"type,omitempty"`
	Value string                     `json:"value,omitempty"`
}

type Summary struct {
	CertificateIssuer      string                 `json:"certificateIssuer"`
	SubjectAlternativeName SubjectAlternativeName `json:"subjectAlternativeName"`
	Extensions
}

type ErrCompareExtensions struct {
	field    string
	expected string
	actual   string
}

func (e *ErrCompareExtensions) Error() string {
	return fmt.Sprintf("expected %s to be \"%s\", got \"%s\"", e.field, e.expected, e.actual)
}

func SummarizeCertificate(cert *x509.Certificate) (Summary, error) {
	extensions, err := ParseExtensions(cert.Extensions)

	if err != nil {
		return Summary{}, err
	}

	san := SubjectAlternativeName{}

	switch {
	case len(cert.URIs) > 0:
		san.Type = SubjectAlternativeNameTypeURI
		san.Value = cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		san.Type = SubjectAlternativeNameTypeEmail
		san.Value = cert.EmailAddresses[0]
	default:
		// TODO: Support OtherName SANs i.e. https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726417--othername-san
		return Summary{}, errors.New("No Subject Alternative Name found")
	}

	return Summary{CertificateIssuer: cert.Issuer.String(), SubjectAlternativeName: san, Extensions: extensions}, nil
}

// CompareExtensions compares two Extensions structs and returns an error if
// any set values in the expected struct not equal. Empty fields in the
// expectedExt struct are ignored.
func CompareExtensions(expectedExt, actualExt Extensions) error {
	expExtValue := reflect.ValueOf(expectedExt)
	actExtValue := reflect.ValueOf(actualExt)

	fields := reflect.VisibleFields(expExtValue.Type())
	for _, field := range fields {
		expectedFieldVal := expExtValue.FieldByName(field.Name)

		// if the expected field is empty, skip it
		if expectedFieldVal.IsValid() && !expectedFieldVal.IsZero() {
			actualFieldVal := actExtValue.FieldByName(field.Name)
			if actualFieldVal.IsValid() {
				if expectedFieldVal.Interface() != actualFieldVal.Interface() {
					return &ErrCompareExtensions{field.Name, fmt.Sprintf("%v", expectedFieldVal.Interface()), fmt.Sprintf("%v", actualFieldVal.Interface())}
				}
			}
		}
	}

	return nil
}
