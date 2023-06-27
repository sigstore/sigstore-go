package verifier

import (
	"testing"

	"github.com/github/sigstore-verifier/pkg/testing/ca"
	"github.com/stretchr/testify/assert"
)

func TestTimestampAuthorityVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	verifier := NewTimestampAuthorityVerifier(virtualSigstore, 1)
	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	err = verifier.Verify(entity)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	verifier2 := NewTimestampAuthorityVerifier(virtualSigstore2, 1)
	err = verifier2.Verify(entity)
	assert.Error(t, err) // different sigstore instance should fail to verify
}