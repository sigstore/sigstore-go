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
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

var SkipArtifactAndIdentitiesPolicy = verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe())

func TestSignatureVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	sigContent, err := entity.SignatureContent()
	assert.NoError(t, err)

	verificationContent, err := entity.VerificationContent()
	assert.NoError(t, err)

	err = verify.VerifySignature(sigContent, verificationContent, virtualSigstore)
	assert.NoError(t, err)

	// should fail to verify with a different signature
	entity2, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
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

	artifact := "Hi, I am an artifact!" //nolint:goconst
	entity, err := virtualSigstore.Sign("foo@example.com", "issuer", []byte(artifact))
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	result, err := verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	assert.Equal(t, result.Signature.Certificate.SubjectAlternativeName, "foo@example.com")
	assert.Equal(t, result.VerifiedTimestamps[0].Type, "Tlog")

	// should fail to verify with a different artifact
	artifact2 := "Hi, I am a different artifact!"
	result, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact2)), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestTooManySubjects(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	tooManySubjectsStatement := in_toto.Statement{}
	for i := 0; i < 1025; i++ {
		tooManySubjectsStatement.Subject = append(tooManySubjectsStatement.Subject, in_toto.Subject{
			Name: fmt.Sprintf("subject-%d", i),
			Digest: map[string]string{
				"sha256": "", // actual content of digest does not matter for this test
			},
		})
	}

	tooManySubjectsStatementBytes, err := json.Marshal(tooManySubjectsStatement)
	assert.NoError(t, err)

	tooManySubjectsEntity, err := virtualSigstore.Attest("foo@example.com", "issuer", tooManySubjectsStatementBytes)
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	artifact := "Hi, I am an artifact!" //nolint:goconst
	_, err = verifier.Verify(tooManySubjectsEntity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
	assert.ErrorContains(t, err, "too many subjects")
}

func TestTooManyDigests(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	tooManyDigestsStatement := in_toto.Statement{}
	tooManyDigestsStatement.Subject = []in_toto.Subject{
		{
			Name:   "subject",
			Digest: make(common.DigestSet),
		},
	}
	tooManyDigestsStatement.Subject[0].Digest["sha512"] = "" // verifier requires that at least one known hash algorithm is present in the digest map
	for i := 0; i < 32; i++ {
		tooManyDigestsStatement.Subject[0].Digest[fmt.Sprintf("digest-%d", i)] = ""
	}

	tooManySubjectsStatementBytes, err := json.Marshal(tooManyDigestsStatement)
	assert.NoError(t, err)

	tooManySubjectsEntity, err := virtualSigstore.Attest("foo@example.com", "issuer", tooManySubjectsStatementBytes)
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	artifact := "Hi, I am an artifact!" //nolint:goconst
	_, err = verifier.Verify(tooManySubjectsEntity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
	assert.ErrorContains(t, err, "too many digests")
}

func TestVerifyEnvelopeWithMultipleArtifactsAndArtifactDigests(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	subjects := make([]in_toto.Subject, 10)
	artifacts := make([]io.Reader, 10)
	artifactDigests := make([]verify.ArtifactDigest, 10)
	// Create ten test subjects
	for i := range 10 {
		s := in_toto.Subject{
			Name: fmt.Sprintf("subject-%d", i),
		}
		subjectBody := fmt.Sprintf("Hi, I am a subject! #%d", i)
		artifacts[i] = strings.NewReader(subjectBody)
		// alternate between sha256 and sha512 when creating the digests
		// so that we can test that the verifier can handle digests created
		// with different algorithms
		if i%2 == 0 {
			digest256 := sha256.Sum256([]byte(subjectBody))
			digest := digest256[:]
			s.Digest = common.DigestSet{
				"sha256": hex.EncodeToString(digest),
			}
			a := verify.ArtifactDigest{
				Algorithm: "sha256",
				Digest:    digest,
			}
			artifactDigests[i] = a
		} else {
			digest512 := sha512.Sum512([]byte(subjectBody))
			digest := digest512[:]
			s.Digest = common.DigestSet{
				"sha512": hex.EncodeToString(digest),
			}
			a := verify.ArtifactDigest{
				Algorithm: "sha512",
				Digest:    digest,
			}
			artifactDigests[i] = a
		}
		subjects[i] = s
	}

	jsonSubjects, err := json.Marshal(subjects)
	assert.NoError(t, err)

	statement := []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":%s,"predicate":{}}`, string(jsonSubjects)))
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.NoError(t, err)

	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifacts(artifacts), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigests(artifactDigests), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	noMatchingArtifacts := []io.Reader{strings.NewReader("some other artifact")}
	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifacts(noMatchingArtifacts), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)

	noMatchingArtifactDigests := []verify.ArtifactDigest{
		{
			Algorithm: "sha256",
			Digest:    []byte("some other artifact"),
		},
	}
	_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigests(noMatchingArtifactDigests), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)
}
