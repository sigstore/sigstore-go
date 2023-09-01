package certificate

import (
	"crypto/x509"
	"errors"
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
	Type  SubjectAlternativeNameType `json:"type"`
	Value string                     `json:"value"`
}

type Summary struct {
	SubjectAlternativeName SubjectAlternativeName `json:"subjectAlternativeName"`
	Extensions
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

	return Summary{Extensions: extensions, SubjectAlternativeName: san}, nil
}
