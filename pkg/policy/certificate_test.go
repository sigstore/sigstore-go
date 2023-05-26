package policy

import (
	"testing"

	"github.com/github/sigstore-verifier/pkg/testing/ca"
	"github.com/stretchr/testify/assert"
)

func TestCertificateSignaturePolicy(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	policy := NewCertificateSignaturePolicy(virtualSigstore)
	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	err = policy.VerifyPolicy(entity)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	policy2 := NewCertificateSignaturePolicy(virtualSigstore2)
	err = policy2.VerifyPolicy(entity)
	assert.Error(t, err) // different sigstore instance should fail to verify
}
