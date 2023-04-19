package policy

import (
	"crypto/x509"

	"github.com/github/sigstore-verifier/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type SignatureProvider interface {
	Signature() ([]byte, error)
}

type KeyIDProvider interface {
	KeyID() (string, error)
}

type CertificateProvider interface {
	CertificateChain() ([]*x509.Certificate, error)
}

type EnvelopeProvider interface {
	Envelope() (*dsse.Envelope, error)
}

type TSASignatureProvider interface {
	TSASignatures() [][]byte // TODO: define type to represent TSA signature
}

type TlogEntryProvider interface {
	TlogEntries() ([]*tlog.Entry, error)
}

type Policy interface {
	VerifyPolicy(any) error
}

func Verify(entity any, policies ...Policy) error {
	for _, policy := range policies {
		if err := policy.VerifyPolicy(entity); err != nil {
			return NewVerificationError(err)
		}
	}
	return nil
}
