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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
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

	assert.Equal(t, result.Signature.Certificate.SubjectAlternativeName.Value, "foofighters@example.com")
	assert.Equal(t, result.VerifiedTimestamps[0].Type, "Tlog")

	// should fail to verify with a different artifact
	artifact2 := "Hi, I am a different artifact!"
	result, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact2)), verify.WithoutIdentitiesUnsafe()))
	assert.Error(t, err)
	assert.Nil(t, result)
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey, hash crypto.Hash) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadVerifier(pk, hash)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

func TestSignatureVerifierMessageSignatureConfigurableSignatureAlgorithms(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	// Test with an ECDSA key with a different curve.
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NoError(t, err)

	virtualSigstore.TrustedMaterial = trustedPublicKeyMaterial(ecdsaKey.Public(), crypto.SHA512)

	artifact := "Hi, I am an artifact!"
	entity, err := virtualSigstore.SignWithPrivateKey("foofighters@example.com", "issuer", []byte(artifact), ecdsaKey, crypto.SHA512)
	assert.NoError(t, err)

	verifier, err := verify.NewSignedEntityVerifier(virtualSigstore, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	result, err := verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	assert.Equal(t, result.VerifiedTimestamps[0].Type, "Tlog")

	// Test with an RSA key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	virtualSigstore.TrustedMaterial = trustedPublicKeyMaterial(rsaKey.Public(), crypto.SHA256)

	entity, err = virtualSigstore.SignWithPrivateKey("foofighters@example.com", "issuer", []byte(artifact), rsaKey, crypto.SHA256)
	assert.NoError(t, err)

	result, err = verifier.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewBufferString(artifact)), verify.WithoutIdentitiesUnsafe()))
	assert.NoError(t, err)

	assert.Equal(t, result.VerifiedTimestamps[0].Type, "Tlog")
}
