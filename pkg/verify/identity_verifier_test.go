// Copyright 2026 The Sigstore Authors.
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

package verify

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/protobuf/encoding/protojson"
)

type mockIdentityTrustedMaterial struct {
	root.BaseTrustedMaterial
	rekorLog  *root.TransparencyLog
	verifiers []root.TimeConstrainedVerifier
}

func (m *mockIdentityTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	if m.rekorLog == nil {
		return nil
	}
	return map[string]*root.TransparencyLog{"log": m.rekorLog}
}

func (m *mockIdentityTrustedMaterial) PublicKeyVerifiers() []root.TimeConstrainedVerifier {
	return m.verifiers
}

type mockVerifiableEntity struct {
	BaseVerifiableEntity
	tlogProof   []byte
	artifactSig []byte
	envelope    EnvelopeContent
}

func (m *mockVerifiableEntity) HasTransparencyLogProof() bool {
	return len(m.tlogProof) > 0
}

func (m *mockVerifiableEntity) TransparencyLogProof() (*bundleV2.TransparencyLogProof, error) {
	if len(m.tlogProof) == 0 {
		return nil, nil
	}
	return &bundleV2.TransparencyLogProof{Proof: m.tlogProof}, nil
}

func (m *mockVerifiableEntity) Signature() ([]byte, error) {
	return m.artifactSig, nil
}

func (m *mockVerifiableEntity) HasEnvelope() bool {
	return m.envelope != nil
}

func (m *mockVerifiableEntity) Envelope() (EnvelopeContent, error) {
	return m.envelope, nil
}

type mockEnvelopeContent struct {
	rawEnv *dsse.Envelope
	stmt   *in_toto.Statement
}

func (m *mockEnvelopeContent) RawEnvelope() *dsse.Envelope            { return m.rawEnv }
func (m *mockEnvelopeContent) Statement() (*in_toto.Statement, error) { return m.stmt, nil }

func TestNewIdentityVerifier(t *testing.T) {
	_, err := NewIdentityVerifier(nil)
	assert.Error(t, err)

	tm := &root.BaseTrustedMaterial{}
	v, err := NewIdentityVerifier(tm)
	require.NoError(t, err)
	assert.NotNil(t, v)

	_, err = v.Verify(&BaseVerifiableEntity{}, NewPolicy(WithoutArtifactUnsafe(), WithoutIdentitiesUnsafe()))
	assert.Error(t, err)
}

func TestNewPKIVerifier(t *testing.T) {
	_, err := NewPKIVerifier(nil)
	assert.Error(t, err)

	tm := &root.BaseTrustedMaterial{}
	_, err = NewPKIVerifier(tm, WithPKISignedTimestamps(0))
	assert.Error(t, err)

	v, err := NewPKIVerifier(tm, WithPKISignedTimestamps(2))
	require.NoError(t, err)
	assert.Equal(t, 2, v.signedTimestampThreshold)

	_, err = v.Verify(&BaseVerifiableEntity{}, NewPolicy(WithoutArtifactUnsafe(), WithoutIdentitiesUnsafe()))
	assert.ErrorIs(t, err, errNotImplemented)
}

func TestNewKeyVerifier(t *testing.T) {
	_, err := NewKeyVerifier(nil)
	assert.Error(t, err)

	tm := &root.BaseTrustedMaterial{}
	vDefault, err := NewKeyVerifier(tm)
	require.NoError(t, err)
	assert.Equal(t, 0, vDefault.signedTimestampThreshold)

	_, err = NewKeyVerifier(tm, WithKeySignedTimestamps(0))
	assert.Error(t, err)

	vTS, err := NewKeyVerifier(tm, WithKeySignedTimestamps(1))
	require.NoError(t, err)
	assert.Equal(t, 1, vTS.signedTimestampThreshold)

	_, err = vTS.Verify(&BaseVerifiableEntity{}, NewPolicy(WithoutArtifactUnsafe(), WithKey()))
	assert.ErrorIs(t, err, errNotImplemented)
}

func TestIdentityVerifier_Verify_Success_PublicKey(t *testing.T) {
	logPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	artifactPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	origin := "mock-origin"

	artifactBytes := []byte("artifact")
	artifactDigest := sha256.Sum256(artifactBytes)
	msgHash := sha256.Sum256(artifactDigest[:])

	prehashedData := append([]byte("c2sp.org/identity-transparency/v1\x00"), msgHash[:]...)
	artifactSig, err := artifactPrivKey.Sign(rand.Reader, prehashedData, nil)
	require.NoError(t, err)

	receiptDigest := sha256.Sum256(artifactSig)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(artifactPrivKey.Public())
	require.NoError(t, err)
	rot := append([]byte("ML-DSA-44"), pubKeyBytes...)
	rootOfTrustHash := sha256.Sum256(rot)

	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, receiptDigest[:]...)
	computedLeafHash := rfc6962.DefaultHasher.HashLeaf(leafHash)

	checkpointBytes := buildSignedCheckpoint(t, logPrivKey, origin, 1, computedLeafHash)
	tlogProof := proof.TLogProof{
		Index:      0,
		Hashes:     nil,
		Checkpoint: checkpointBytes,
	}

	entity := &mockVerifiableEntity{
		tlogProof:   tlogProof.Marshal(),
		artifactSig: artifactSig,
	}

	artifactVerifier, err := signature.LoadVerifier(artifactPrivKey.Public(), 0)
	require.NoError(t, err)

	tm := &mockIdentityTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:   "https://" + origin,
			PublicKey: logPrivKey.Public(),
		},
		verifiers: []root.TimeConstrainedVerifier{
			root.NewExpiringKey(artifactVerifier, time.Time{}, time.Time{}),
		},
	}

	verifier, err := NewIdentityVerifier(tm)
	require.NoError(t, err)

	pb := NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey())
	res, err := verifier.Verify(entity, pb)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Verified)
	assert.Len(t, res.Timestamps, 1)

	// WithArtifactDigest with sha256 succeeds; non-sha256 or wrong length fails
	res, err = verifier.Verify(entity, NewPolicy(WithArtifactDigest("sha256", artifactDigest[:]), WithKey()))
	require.NoError(t, err)
	assert.True(t, res.Verified)

	_, err = verifier.Verify(entity, NewPolicy(WithArtifactDigest("sha512", artifactDigest[:]), WithKey()))
	assert.ErrorContains(t, err, "IdentityVerifier requires sha256 artifact digest algorithm")

	_, err = verifier.Verify(entity, NewPolicy(WithArtifactDigest("sha256", []byte("short")), WithKey()))
	assert.ErrorContains(t, err, "IdentityVerifier requires a 32-byte sha256 artifact digest")

	// WithContext on a context-less bundle fails
	ctxDigest := sha256.Sum256([]byte("expected-context"))
	_, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey(), WithContext(ctxDigest[:])))
	assert.ErrorContains(t, err, "context in tlog extra data does not match policy context")

	// WithContext with non-32-byte slice fails policy construction
	_, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey(), WithContext([]byte("short"))))
	assert.ErrorContains(t, err, "context must be a 32-byte SHA-256 digest")

	// Bundle signed with context verifies with matching WithContext and fails with mismatched WithContext
	extraData := []byte("context:" + hex.EncodeToString(ctxDigest[:]))
	extraClaims, err := parseExtraData(extraData)
	require.NoError(t, err)
	_, ctxHashes, err := computeContextClaimHashes(extraClaims)
	require.NoError(t, err)

	ctxPrehashedData := append([]byte("c2sp.org/identity-transparency/v1\x00"), msgHash[:]...)
	ctxPrehashedData = append(ctxPrehashedData, ctxHashes...)
	ctxSig, err := artifactPrivKey.Sign(rand.Reader, ctxPrehashedData, nil)
	require.NoError(t, err)
	ctxReceiptDigest := sha256.Sum256(ctxSig)

	ctxLeaf := []byte{0x01}
	ctxLeaf = append(ctxLeaf, rootOfTrustHash[:]...)
	ctxLeaf = append(ctxLeaf, msgHash[:]...)
	ctxLeaf = append(ctxLeaf, ctxHashes...)
	ctxLeaf = append(ctxLeaf, ctxReceiptDigest[:]...)
	ctxLeafHash := rfc6962.DefaultHasher.HashLeaf(ctxLeaf)

	ctxProof := proof.TLogProof{
		Index:      0,
		Hashes:     nil,
		Checkpoint: buildSignedCheckpoint(t, logPrivKey, origin, 1, ctxLeafHash),
		ExtraData:  extraData,
	}
	ctxEntity := &mockVerifiableEntity{
		tlogProof:   ctxProof.Marshal(),
		artifactSig: ctxSig,
	}
	res, err = verifier.Verify(ctxEntity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey(), WithContext(ctxDigest[:])))
	require.NoError(t, err)
	assert.True(t, res.Verified)

	wrongCtx := sha256.Sum256([]byte("wrong-context"))
	_, err = verifier.Verify(ctxEntity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey(), WithContext(wrongCtx[:])))
	assert.ErrorContains(t, err, "context in tlog extra data does not match policy context")

	// Unscoped policy (without WithContext) rejects a bundle signed with a context
	_, err = verifier.Verify(ctxEntity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey()))
	assert.ErrorContains(t, err, "context in tlog extra data does not match policy context")

	// WithContext without WithKey fails policy validation
	_, err = verifier.Verify(ctxEntity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithoutIdentitiesUnsafe(), WithContext(ctxDigest[:])))
	assert.ErrorContains(t, err, "WithContext must be used with WithKey")

	// Expired key should fail verification
	expiredTM := &mockIdentityTrustedMaterial{
		rekorLog: tm.rekorLog,
		verifiers: []root.TimeConstrainedVerifier{
			root.NewExpiringKey(artifactVerifier, time.Unix(100, 0), time.Unix(200, 0)),
		},
	}
	expiredVerifier, err := NewIdentityVerifier(expiredTM)
	require.NoError(t, err)
	_, err = expiredVerifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithKey()))
	assert.ErrorContains(t, err, "no matching trusted public key")
}

func TestIdentityVerifier_Verify_Success_OIDC(t *testing.T) {
	logPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	origin := "mock-origin"

	artifactBytes := []byte("artifact")
	artifactDigest := sha256.Sum256(artifactBytes)
	msgHash := sha256.Sum256(artifactDigest[:])
	var receiptDigest [32]byte

	extraData := []byte(
		"issuer:https://example.com\n" +
			"identity:foo@bar.com\n" +
			"build-signer-uri:https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0\n" +
			"runner-environment:github-hosted\n" +
			"source-repository-uri:https://github.com/org/repo",
	)
	extraClaims, err := parseExtraData(extraData)
	require.NoError(t, err)
	contextHashes := computeOIDCClaimHashes(extraClaims)

	rootOfTrustHash := sha256.Sum256([]byte("https://example.com"))

	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, contextHashes...)
	leafHash = append(leafHash, receiptDigest[:]...)
	computedLeafHash := rfc6962.DefaultHasher.HashLeaf(leafHash)

	checkpointBytes := buildSignedCheckpoint(t, logPrivKey, origin, 1, computedLeafHash)
	tlogProof := proof.TLogProof{
		Index:      0,
		Hashes:     nil,
		Checkpoint: checkpointBytes,
		ExtraData:  extraData,
	}

	entity := &mockVerifiableEntity{
		tlogProof: tlogProof.Marshal(),
	}

	tm := &mockIdentityTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:   "https://" + origin,
			PublicKey: logPrivKey.Public(),
		},
	}

	verifier, err := NewIdentityVerifier(tm)
	require.NoError(t, err)

	// 1. Policy requiring only issuer and identity succeeds without requiring other logged claims
	certID, err := NewShortCertificateIdentity("https://example.com", "", "foo@bar.com", "")
	require.NoError(t, err)

	pb := NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithCertificateIdentity(certID))
	res, err := verifier.Verify(entity, pb)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Verified)
	require.NotNil(t, res.VerifiedIdentity)
	assert.Equal(t, "foo@bar.com", res.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName)

	// 2. Policy requiring issuer, identity, and a subset of optional extensions succeeds when matched
	sanMatcher, err := NewSANMatcher("foo@bar.com", "")
	require.NoError(t, err)
	issuerMatcher, err := NewIssuerMatcher("https://example.com", "")
	require.NoError(t, err)
	extCertID, err := NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{
		BuildSignerURI:    "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
		RunnerEnvironment: "github-hosted",
	})
	require.NoError(t, err)
	res, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithCertificateIdentity(extCertID)))
	require.NoError(t, err)
	assert.True(t, res.Verified)

	// 3. Policy with a mismatched optional extension fails verification
	mismatchExtCertID, err := NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{
		RunnerEnvironment: "self-hosted",
	})
	require.NoError(t, err)
	_, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithCertificateIdentity(mismatchExtCertID)))
	assert.ErrorContains(t, err, "failed to verify identity against policy")

	// 4. Mismatched identity fails verification
	wrongID, err := NewShortCertificateIdentity("https://example.com", "", "other@bar.com", "")
	require.NoError(t, err)
	_, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithCertificateIdentity(wrongID)))
	assert.ErrorContains(t, err, "failed to verify identity against policy")

	// 5. CertificateIdentity missing identity (SAN) or issuer fails construction and verification
	_, err = NewShortCertificateIdentity("https://example.com", "", "", "")
	assert.ErrorContains(t, err, "there must be subject alternative name criteria")
	_, err = NewShortCertificateIdentity("", "", "foo@bar.com", "")
	assert.ErrorContains(t, err, "must specify Issuer criteria")

	missingSANPolicy := CertificateIdentity{Issuer: issuerMatcher}
	_, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithCertificateIdentity(missingSANPolicy)))
	assert.ErrorContains(t, err, "there must be subject alternative name criteria")

	missingIssuerPolicy := CertificateIdentity{SubjectAlternativeName: sanMatcher}
	_, err = verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(artifactBytes)), WithCertificateIdentity(missingIssuerPolicy)))
	assert.ErrorContains(t, err, "must specify Issuer criteria")
}

func TestIdentityVerifier_Verify_Success_DSSE(t *testing.T) {
	logPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	origin := "mock-origin"

	subjectContent := []byte("subject-artifact")
	subjectDigest := sha256.Sum256(subjectContent)

	stmt := &in_toto.Statement{
		Type: in_toto.StatementTypeUri,
		Subject: []*in_toto.ResourceDescriptor{
			{
				Name: "subject.txt",
				Digest: map[string]string{
					"sha256": hex.EncodeToString(subjectDigest[:]),
				},
			},
		},
		PredicateType: "https://example.com/predicate/v1",
	}
	stmtBytes, err := protojson.Marshal(stmt)
	require.NoError(t, err)

	payloadType := "application/vnd.in-toto+json"
	rawEnv := &dsse.Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(stmtBytes),
	}

	pae := dsse.PAE(payloadType, stmtBytes)
	paeDigest := sha256.Sum256(pae)
	msgHash := sha256.Sum256(paeDigest[:])
	var receiptDigest [32]byte

	extraData := []byte("issuer:https://example.com\nidentity:foo@bar.com")
	extraClaims, err := parseExtraData(extraData)
	require.NoError(t, err)
	contextHashes := computeOIDCClaimHashes(extraClaims)

	rootOfTrustHash := sha256.Sum256([]byte("https://example.com"))

	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, contextHashes...)
	leafHash = append(leafHash, receiptDigest[:]...)
	computedLeafHash := rfc6962.DefaultHasher.HashLeaf(leafHash)

	checkpointBytes := buildSignedCheckpoint(t, logPrivKey, origin, 1, computedLeafHash)
	tlogProof := proof.TLogProof{
		Index:      0,
		Hashes:     nil,
		Checkpoint: checkpointBytes,
		ExtraData:  extraData,
	}

	entity := &mockVerifiableEntity{
		tlogProof: tlogProof.Marshal(),
		envelope: &mockEnvelopeContent{
			rawEnv: rawEnv,
			stmt:   stmt,
		},
	}

	tm := &mockIdentityTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:   "https://" + origin,
			PublicKey: logPrivKey.Public(),
		},
	}

	verifier, err := NewIdentityVerifier(tm)
	require.NoError(t, err)

	res, err := verifier.Verify(entity, NewPolicy(WithArtifact(bytes.NewReader(subjectContent)), WithoutIdentitiesUnsafe()))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Verified)
	require.NotNil(t, res.Statement)
	assert.Equal(t, "https://example.com/predicate/v1", res.Statement.PredicateType)
}
