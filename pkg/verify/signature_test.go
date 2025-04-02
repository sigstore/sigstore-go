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
	"crypto"
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
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
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

func TestCompatibilityAlgorithms(t *testing.T) {
	tts := []struct {
		hash            crypto.Hash
		pkDetails       v1.PublicKeyDetails
		noCompatSucceed bool
	}{
		{
			hash:            crypto.SHA256,
			pkDetails:       v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			noCompatSucceed: true,
		},
		{
			hash:            crypto.SHA256,
			pkDetails:       v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256,
			noCompatSucceed: true,
		},
		{
			hash:            crypto.SHA384,
			pkDetails:       v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
			noCompatSucceed: true,
		},
		{
			hash: crypto.SHA256,
			//nolint:staticcheck // Need to use deprecated field for backwards compatibility
			pkDetails:       v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_256,
			noCompatSucceed: false,
		},
		{
			hash: crypto.SHA256,
			//nolint:staticcheck // Need to use deprecated field for backwards compatibility
			pkDetails:       v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_256,
			noCompatSucceed: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.pkDetails.String(), func(t *testing.T) {
			virtualSigstore, err := ca.NewVirtualSigstoreCustom(tt.pkDetails)
			assert.NoError(t, err)

			// Create a test artifact
			artifact := "Hi, I am an artifact!" //nolint:goconst
			h := tt.hash.New()
			h.Write([]byte(artifact))
			digest := h.Sum(nil)
			var digestString string
			switch tt.hash {
			case crypto.SHA256:
				digestString = "sha256"
			case crypto.SHA384:
				digestString = "sha384"
			case crypto.SHA512:
				digestString = "sha512"
			}

			// Create a message signature with SHA-256 (older client behavior)
			entity, err := virtualSigstore.Sign("foo@example.com", "issuer", []byte(artifact))
			assert.NoError(t, err)

			verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
			assert.NoError(t, err)

			// First try without compatibility algorithms
			_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
			if tt.noCompatSucceed {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}

			// Now try with compatibility algorithms enabled - should succeed
			_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe(), verify.WithCompatibilityAlgorithms()))
			assert.NoError(t, err)

			// Test with artifact digest instead of full artifact
			_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest(digestString, digest), verify.WithoutIdentitiesUnsafe(), verify.WithCompatibilityAlgorithms()))
			assert.NoError(t, err)

			// Test with wrong digest - should fail even with compatibility algorithms
			_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest(digestString, []byte("wrong")), verify.WithoutIdentitiesUnsafe(), verify.WithCompatibilityAlgorithms()))
			assert.Error(t, err)

			// Test with wrong artifact - should fail even with compatibility algorithms
			_, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString("wrong artifact")), verify.WithoutIdentitiesUnsafe(), verify.WithCompatibilityAlgorithms()))
			assert.Error(t, err)
		})
	}
}
