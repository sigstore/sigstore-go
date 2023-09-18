package verify

// import (
// 	"testing"
//
// 	"github.com/github/sigstore-verifier/pkg/testing/ca"
// 	"github.com/stretchr/testify/assert"
// )

// TODO: adapt for new VerifySignature?
// func TestSignatureVerifier(t *testing.T) {
// 	virtualSigstore, err := ca.NewVirtualSigstore()
// 	assert.NoError(t, err)
//
// 	verifier := NewSignatureVerifier(virtualSigstore)
// 	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
// 	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", statement)
// 	assert.NoError(t, err)
//
// 	err = verifier.Verify(entity)
// 	assert.NoError(t, err)
//
// 	virtualSigstore2, err := ca.NewVirtualSigstore()
// 	assert.NoError(t, err)
//
// 	verifier2 := NewSignatureVerifier(virtualSigstore2)
// 	err = verifier2.Verify(entity)
// 	assert.Error(t, err) // different sigstore instance should fail to verify
// }
