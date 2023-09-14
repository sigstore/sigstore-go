package verify

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/github/sigstore-verifier/pkg/fulcio/certificate"
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
func (s SubjectAlternativeNameMatcher) Verify(actualCert certificate.Summary) bool {
	var typeMatches bool
	var valueMatches bool
	var regexMatches bool

	// if a {SAN Type, Value, Regexp} was not specified, default to true
	if s.SubjectAlternativeName.Type != "" {
		typeMatches = s.Type == actualCert.SubjectAlternativeName.Type
	} else {
		typeMatches = true
	}

	if s.SubjectAlternativeName.Value != "" {
		valueMatches = s.Value == actualCert.SubjectAlternativeName.Value
	} else {
		valueMatches = true
	}

	if s.Regexp.String() != "" {
		regexMatches = s.Regexp.MatchString(actualCert.SubjectAlternativeName.Value)
	} else {
		regexMatches = true
	}

	return typeMatches && valueMatches && regexMatches
}

func NewCertificateIdentity(sanMatcher SubjectAlternativeNameMatcher, extensions certificate.Extensions) (CertificateIdentity, error) {
	certID := CertificateIdentity{SubjectAlternativeName: sanMatcher, Extensions: extensions}

	if certID.Issuer == "" {
		return CertificateIdentity{}, errors.New("When verifying a certificate identity, the Issuer field can't be empty")
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

func (i CertificateIdentities) Verify(cert certificate.Summary) (*CertificateIdentity, error) {
	for _, ci := range i {
		if ci.Verify(cert) {
			return &ci, nil
		}
	}

	return nil, errors.New("No matching certificate identity found")
}

// Verify checks if the actualCert matches the CertificateIdentity's SAN and
// any of the provided OID extension values. Any empty values are ignored.
func (c CertificateIdentity) Verify(actualCert certificate.Summary) bool {
	sanMatches := c.SubjectAlternativeName.Verify(actualCert)
	extensionsMatch := certificate.CompareExtensions(c.Extensions, actualCert.Extensions)

	return sanMatches && extensionsMatch
}
