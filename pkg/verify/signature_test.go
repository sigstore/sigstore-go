package verify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/github/sigstore-go/pkg/testing/ca"
	"github.com/github/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestSignatureVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foofighters@example.com", "issuer", statement)
	assert.NoError(t, err)

	sigContent, err := entity.SignatureContent()
	assert.NoError(t, err)

	verificationContent, err := entity.VerificationContent()
	assert.NoError(t, err)

	err = verify.VerifySignature(sigContent, verificationContent, virtualSigstore)
	assert.NoError(t, err)

	// should fail to verify with a different signature
	entity2, err := virtualSigstore.Attest("foofighters@example.com", "issuer", statement)
	assert.NoError(t, err)

	sigContent2, err := entity2.SignatureContent()
	assert.NoError(t, err)

	err = verify.VerifySignature(sigContent2, verificationContent, virtualSigstore)
	assert.Error(t, err)
}

func TestEnvelopeSubject(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	subjectBody := "Hi, I am a subject!"
	digest256 := sha256.Sum256([]byte(subjectBody))
	digest := digest256[:]
	digest256hex := hex.EncodeToString(digest)

	statement := []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"%s"}}],"predicate":{}}`, digest256hex))
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1))
	assert.NoError(t, err)

	_, err = verifier.VerifyUnsafe(entity)
	assert.NoError(t, err)

	_, err = verifier.VerifyUnsafe(entity, verify.WithArtifact(bytes.NewBufferString(subjectBody)))
	assert.NoError(t, err)

	_, err = verifier.VerifyUnsafe(entity, verify.WithArtifactDigest("sha256", digest))
	assert.NoError(t, err)

	// Error: incorrect artifact
	_, err = verifier.VerifyUnsafe(entity, verify.WithArtifact(bytes.NewBufferString("Hi, I am a different subject!")))
	assert.Error(t, err)

	// Error: incorrect digest algorithm
	_, err = verifier.VerifyUnsafe(entity, verify.WithArtifactDigest("sha512", digest))
	assert.Error(t, err)
}

func TestSignatureVerifierMessageSignature(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	artifact := "Hi, I am an artifact!"
	entity, err := virtualSigstore.Sign("foofighters@example.com", "issuer", []byte(artifact))
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1))
	assert.NoError(t, err)

	result, err := verifier.VerifyUnsafe(entity, verify.WithArtifact(bytes.NewBufferString(artifact)))
	assert.NoError(t, err)

	assert.Equal(t, result.Signature.Certificate.SubjectAlternativeName.Value, "foofighters@example.com")
	assert.Equal(t, result.VerifiedTimestamps[0].Type, "Tlog")

	// should fail to verify with a different artifact
	artifact2 := "Hi, I am a different artifact!"
	result, err = verifier.VerifyUnsafe(entity, verify.WithArtifact(bytes.NewBufferString(artifact2)))
	assert.Error(t, err)
	assert.Nil(t, result)
}
