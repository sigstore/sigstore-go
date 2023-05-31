package policy

import (
	"testing"

	"github.com/github/sigstore-verifier/pkg/testing/ca"
	"github.com/stretchr/testify/assert"
)

func TestTimestampAuthorityPolicy(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	policy := NewTimestampAuthorityPolicy(virtualSigstore, 1)
	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	err = policy.VerifyPolicy(entity)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	policy2 := NewTimestampAuthorityPolicy(virtualSigstore2, 1)
	err = policy2.VerifyPolicy(entity)
	assert.Error(t, err) // different sigstore instance should fail to verify
}
