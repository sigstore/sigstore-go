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

package verify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

var SkipArtifactAndIdentitiesPolicy = verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe())

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

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.NoError(t, err)

	_, err = verifier.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NoError(t, err)

	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(subjectBody)), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	// Error: incorrect artifact
	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString("Hi, I am a different subject!")), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)

	// Error: incorrect digest algorithm
	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest("sha512", digest), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)
}

func TestSignatureVerifierMessageSignature(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	artifact := "Hi, I am an artifact!"
	entity, err := virtualSigstore.Sign("foofighters@example.com", "issuer", []byte(artifact))
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	result, err := verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	assert.Equal(t, result.Signature.Certificate.SubjectAlternativeName, "foofighters@example.com")
	assert.Equal(t, result.VerifiedTimestamps[0].Type, "Tlog")

	// should fail to verify with a different artifact
	artifact2 := "Hi, I am a different artifact!"
	result, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact2)), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)
	assert.Nil(t, result)
}
