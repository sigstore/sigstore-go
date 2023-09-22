package verify_test

import (
	"testing"
	"time"

	"github.com/github/sigstore-verifier/pkg/testing/ca"
	"github.com/github/sigstore-verifier/pkg/tlog"
	"github.com/github/sigstore-verifier/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestTlogVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", statement)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, false)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore2, 1, false)
	assert.Error(t, err) // different sigstore instance should fail to verify

	// Attempt to use tlog with integrated time outside certificate validity.
	//
	// This time was chosen assuming the Fulcio signing certificate expires
	// after 5 minutes, but while the TSA intermediate is still valid (2 hours).
	entity, err = virtualSigstore.AttestAtTime("foo@fighters.com", "issuer", statement, time.Now().Add(30*time.Minute))
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, false)
	assert.Error(t, err)
}

type dupTlogEntity struct {
	*ca.TestEntity
}

func (e *dupTlogEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}

	return append(entries, entries[0]), nil
}

func TestDuplicateTlogEntries(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foofighters@example.com", "issuer", statement)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(&dupTlogEntity{entity}, virtualSigstore, 1, false)
	assert.Error(t, err) // duplicate tlog entries should fail to verify
}
