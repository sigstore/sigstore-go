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
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"unicode"

	"encoding/hex"
	"encoding/json"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestVerifierInitialization(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")

	// can't create a verifier without specifying either tlog or tsa
	_, err := verify.NewVerifier(tr)
	assert.NotNil(t, err)

	// can create a verifier with both of them
	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.Nil(t, err)

	// unless we are really sure we want a verifier without either tlog or tsa
	_, err = verify.NewVerifier(tr, verify.WithCurrentTime())
	assert.Nil(t, err)

	// can configure the verifiers with thresholds
	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(2), verify.WithSignedTimestamps(10))

	assert.Nil(t, err)

	// can't configure them with < 1 thresholds
	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(0), verify.WithSignedTimestamps(-10))
	assert.Error(t, err)
}

func TestVerifierInitRequiresTimestamp(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")

	_, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1))
	assert.Error(t, err)
	if !strings.Contains(err.Error(), "you must specify at least one of") {
		t.Errorf("expected error missing timestamp verifier, got: %v", err)
	}

	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	assert.NoError(t, err)
	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.NoError(t, err)
	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)
	_, err = verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithCurrentTime())
	assert.NoError(t, err)
}

// Testing a bundle:
// - signed by public good
// - one tlog entry
// - zero tsa entries

func TestEntitySignedByPublicGoodWithTlogVerifiesSuccessfully(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, res)

	assert.NotNil(t, res.Statement)
	assert.Equal(t, "https://slsa.dev/provenance/v1", res.Statement.PredicateType)
	assert.NotNil(t, res.Signature)
	assert.NotNil(t, res.Signature.Certificate)
	assert.Equal(t, "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main", res.Signature.Certificate.SubjectAlternativeName)
	assert.NotEmpty(t, res.VerifiedTimestamps)
	assert.Equal(t, "https://rekor.sigstore.dev", res.VerifiedTimestamps[0].URI)

	// verifies with integrated timestamp threshold too
	v, err = verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	assert.NoError(t, err)
	res, err = v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestEntitySignedByPublicGoodWithoutTimestampsVerifiesSuccessfully(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

func TestEntitySignedByPublicGoodWithHighTlogThresholdFails(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(2), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	if !strings.Contains(err.Error(), "not enough verified log entries from transparency log") {
		t.Errorf("expected error not meeting log entry threshold, got: %v", err)
	}
}

func TestEntitySignedByPublicGoodWithoutVerifyingLogEntryFails(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	if !strings.Contains(err.Error(), "threshold not met for verified signed & log entry integrated timestamps") {
		t.Errorf("expected error not meeting timestamp threshold without entry verification, got: %v", err)
	}

	// also fails trying to use integrated timestamps without verifying the log
	v, err = verify.NewVerifier(tr, verify.WithIntegratedTimestamps(1))
	assert.NoError(t, err)
	res, err = v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	if !strings.Contains(err.Error(), "threshold not met for verified log entry integrated timestamps") {
		t.Errorf("expected error not meeting integrated timestamp threshold without entry verification, got: %v", err)
	}
}

func TestEntitySignedByPublicGoodWithHighLogTimestampThresholdFails(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(2))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	if !strings.Contains(err.Error(), "threshold not met for verified log entry integrated timestamps") {
		t.Errorf("expected error not meeting log entry integrated timestamp threshold, got: %v", err)
	}
}

func TestEntitySignedByPublicGoodExpectingTSAFails(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	if !strings.Contains(err.Error(), "threshold not met for verified signed timestamps") {
		t.Errorf("expected error not meeting signed timestamp threshold, got: %v", err)
	}
}

func TestEntitySignedByPublicGoodWithHighObserverTimestampThresholdFails(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(2))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	if !strings.Contains(err.Error(), "threshold not met for verified signed & log entry integrated timestamps") {
		t.Errorf("expected error not meeting observer timestamp threshold, got: %v", err)
	}
}

func TestEntityWithOthernameSan(t *testing.T) {
	tr := data.TrustedRoot(t, "scaffolding.json")
	entity := data.Bundle(t, "othername.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	assert.NoError(t, err)

	digest, err := hex.DecodeString("bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b")
	assert.NoError(t, err)

	certID, err := verify.NewShortCertificateIdentity("http://oidc.local:8080", "", "foo!oidc.local", "")
	assert.NoError(t, err)
	res, err := v.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(certID)))
	assert.NoError(t, err)
	assert.NotNil(t, res)

	assert.Equal(t, res.VerifiedIdentity.Issuer.Issuer, "http://oidc.local:8080")
	assert.Equal(t, res.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName, "foo!oidc.local")

	// an email address doesn't verify
	certID, err = verify.NewShortCertificateIdentity("http://oidc.local:8080", "", "foo@oidc.local", "")
	assert.NoError(t, err)
	_, err = v.Verify(entity, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(certID)))
	assert.Error(t, err)
}

// Now we test policy:

func TestVerifyPolicyOptionErors(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	verifier, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.Nil(t, err)

	goodCertID, err := verify.NewShortCertificateIdentity(verify.ActionsIssuerValue, "", "", verify.SigstoreSanRegex)
	assert.Nil(t, err)

	digest, _ := hex.DecodeString("46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c")

	// first, we demonstrate a happy path combination:
	noArtifactHappyPath := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(goodCertID))
	p, err := noArtifactHappyPath.BuildConfig()
	assert.Nil(t, err)
	assert.NotNil(t, p)

	assert.False(t, p.RequireArtifact())
	assert.True(t, p.RequireIdentities())

	// ---

	noArtifactNoCertHappyPath := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe())
	p, err = noArtifactNoCertHappyPath.BuildConfig()
	assert.Nil(t, err)
	assert.NotNil(t, p)

	assert.False(t, p.RequireArtifact())
	assert.False(t, p.RequireIdentities())

	// ---

	yesArtifactNoCertHappyPath := verify.NewPolicy(verify.WithArtifactDigest("sha512", digest), verify.WithoutIdentitiesUnsafe())
	p, err = yesArtifactNoCertHappyPath.BuildConfig()
	assert.Nil(t, err)
	assert.NotNil(t, p)

	assert.True(t, p.RequireArtifact())
	assert.False(t, p.RequireIdentities())

	// ---

	noArtifactKeyHappyPath := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithKey())
	p, err = noArtifactKeyHappyPath.BuildConfig()
	assert.Nil(t, err)
	assert.NotNil(t, p)

	assert.True(t, p.RequireSigningKey())
	assert.False(t, p.RequireIdentities())

	// let's exercise the different error cases!
	// 1. can't combine WithoutArtifactUnsafe with other Artifact options
	// technically a hack that requires casting but better safe than sorry:
	badArtifactComboPolicy1 := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.PolicyOption(verify.WithArtifactDigest("sha512", digest)), verify.WithCertificateIdentity(goodCertID))

	_, err = badArtifactComboPolicy1.BuildConfig()
	assert.NotNil(t, err)

	// imho good to check that the verify func also fails
	_, err = verifier.Verify(entity, badArtifactComboPolicy1)
	assert.NotNil(t, err)

	// 2. can't combine several artifact policies
	badArtifactComboPolicy2 := verify.NewPolicy(verify.WithArtifact(strings.NewReader("")), verify.PolicyOption(verify.WithArtifactDigest("sha512", digest)), verify.WithCertificateIdentity(goodCertID))

	_, err = badArtifactComboPolicy2.BuildConfig()
	assert.NotNil(t, err)

	_, err = verifier.Verify(entity, badArtifactComboPolicy2)
	assert.NotNil(t, err)

	// 3. always have to provide _an_ identity option, even tho it will compile:
	badIdentityPolicyOpts := verify.NewPolicy(verify.WithoutArtifactUnsafe())
	_, err = badIdentityPolicyOpts.BuildConfig()
	assert.NotNil(t, err)

	_, err = verifier.Verify(entity, badIdentityPolicyOpts)
	assert.NotNil(t, err)

	// 4. can't combine incompatible identity options
	badIdentityPolicyCombo := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe(), verify.WithCertificateIdentity(goodCertID))
	_, err = badIdentityPolicyCombo.BuildConfig()
	assert.NotNil(t, err)

	_, err = verifier.Verify(entity, badIdentityPolicyCombo)
	assert.NotNil(t, err)

	// 5. can't expect certificate and key signature
	badIdentityPolicyCombo2 := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(goodCertID), verify.WithKey())
	_, err = badIdentityPolicyCombo2.BuildConfig()
	assert.NotNil(t, err)
}

func TestEntitySignedByPublicGoodWithCertificateIdentityVerifiesSuccessfully(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	goodCI, _ := verify.NewShortCertificateIdentity(verify.ActionsIssuerValue, "", "", verify.SigstoreSanRegex)
	badCI, _ := verify.NewShortCertificateIdentity(verify.ActionsIssuerValue, "", "BadSANValue", "")

	verifier, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))

	assert.Nil(t, err)

	digest, err := hex.DecodeString("46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c")
	assert.Nil(t, err)

	res, err := verifier.Verify(entity,
		verify.NewPolicy(verify.WithArtifactDigest("sha512", digest),
			verify.WithCertificateIdentity(badCI),
			verify.WithCertificateIdentity(goodCI)))
	assert.Nil(t, err)

	assert.Equal(t, res.VerifiedIdentity.Issuer.Issuer, verify.ActionsIssuerValue)

	// but if only pass in the bad CI, it will fail:
	res, err = verifier.Verify(entity,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha512", digest),
			verify.WithCertificateIdentity(badCI)))
	assert.NotNil(t, err)
	assert.Nil(t, res)

	// and if the digest is off, verification fails
	badDigest, err := hex.DecodeString("56d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c")
	assert.Nil(t, err)

	res, err = verifier.Verify(entity,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha512", badDigest),
			verify.WithCertificateIdentity(goodCI)))
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

// TODO test bundles:
// - signed with a key, not a fulcio cert, i.e. npm
// - with duplicate tlog entries
// - with duplicate tsa entries
// - with tlog entries that do not refer to the verification content
// - with tsa entries that do not refer to the verification content
// - with an artifact to be verified
// - with a messagesignature (and artifact)

func TestThatAllTheJSONKeysStartWithALowerCase(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	verifier, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.Nil(t, err)

	res, err := verifier.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Nil(t, err)

	rawJSON, err := json.Marshal(res)
	assert.Nil(t, err)

	var unmarshaledJSON interface{}

	err = json.Unmarshal(rawJSON, &unmarshaledJSON)
	assert.Nil(t, err)

	ensureKeysBeginWithLowercase(t, unmarshaledJSON)
}

func ensureKeysBeginWithLowercase(t *testing.T, obj interface{}) {
	switch v := obj.(type) {
	case map[string]interface{}:
		for key, val := range v {
			r := []rune(key)

			assert.Equal(t, string(unicode.ToLower(r[0]))+string(r[1:]), key)
			ensureKeysBeginWithLowercase(t, val)
		}
	case []interface{}:
		for _, val := range v {
			ensureKeysBeginWithLowercase(t, val)
		}
	}
}

func TestSigstoreBundle2Sig(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "dsse-2sigs.sigstore.json")

	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.True(t, errors.Is(err, verify.ErrDSSEInvalidSignatureCount))
	assert.Nil(t, res)
}

func TestStatementSerializesToValidInTotoStatement(t *testing.T) {
	statement := in_toto.Statement{}
	statement.Type = "https://in-toto.io/Statement/v0.1"
	statement.PredicateType = "https://example.org/predicate"
	statement.Subject = []*in_toto.ResourceDescriptor{
		{
			Name: "artifact-name",
			Digest: map[string]string{
				"sha256": "artifact-digest",
			},
		},
	}
	statement.Predicate = &structpb.Struct{
		Fields: map[string]*structpb.Value{},
	}

	result := verify.NewVerificationResult()
	result.Statement = &statement

	// marshal the statement to JSON
	resultJSON, err := json.Marshal(result)
	assert.NoError(t, err)
	want := `
	{
		"mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
		"verifiedTimestamps": null,
		"statement": {
			"_type": "https://in-toto.io/Statement/v0.1",
			"predicateType": "https://example.org/predicate",
			"subject": [
				{
					"name": "artifact-name",
					"digest": {
						"sha256": "artifact-digest"
					}
				}
			],
			"predicate": {}
		}
	}`
	assert.JSONEq(t, want, string(resultJSON))

	// unmarshal the JSON back to a VerificationResult
	result2 := verify.NewVerificationResult()
	err = json.Unmarshal(resultJSON, result2)
	assert.NoError(t, err)
	assert.Equal(t, result.MediaType, result2.MediaType)
	assert.Equal(t, result.Statement, result2.Statement)
}

func TestCertificateSignedEntityWithSCTsRequiredVerifiesSuccessfully(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(
		tr,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	assert.NoError(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.NotNil(t, res.Signature)
	assert.NotNil(t, res.Signature.Certificate)
}

func TestForcedKeySignedEntityWithSCTsRequiredFails(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")

	v, err := verify.NewVerifier(
		tr,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	assert.NoError(t, err)

	// Wrap existing data to force key-signed behavior as current data is signed by a certificate
	keySignedEntity := &keySignedEntityWrapper{
		SignedEntity: entity,
		forceKey:     true,
	}

	res, err := v.Verify(keySignedEntity, SkipArtifactAndIdentitiesPolicy)
	assert.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t,
		"SCTs required but bundle is signed with a public key, which cannot contain SCTs",
		err.Error(),
	)
}

type keySignedEntityWrapper struct {
	verify.SignedEntity
	forceKey bool
}

func (w *keySignedEntityWrapper) VerificationContent() (verify.VerificationContent, error) {
	vc, err := w.SignedEntity.VerificationContent()
	if err != nil {
		return nil, err
	}
	return &keySignedVerificationContent{
		VerificationContent: vc,
		forceKey:            w.forceKey,
	}, nil
}

type keySignedVerificationContent struct {
	verify.VerificationContent
	forceKey bool
}

func (k *keySignedVerificationContent) PublicKey() verify.PublicKeyProvider {
	if k.forceKey {
		return &mockPublicKeyProvider{keyBytes: []byte("mock-public-key")}
	}
	return k.VerificationContent.PublicKey()
}

func (k *keySignedVerificationContent) Certificate() *x509.Certificate {
	if k.forceKey {
		return nil
	}
	return k.VerificationContent.Certificate()
}

type mockPublicKeyProvider struct {
	keyBytes []byte
}

func (p *mockPublicKeyProvider) PublicKey() ([]byte, error) {
	return p.keyBytes, nil
}

func (p *mockPublicKeyProvider) Hint() string {
	return "mock"
}
