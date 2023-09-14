package verifier

import (
	"testing"
	"unicode"

	"encoding/json"

	"github.com/github/sigstore-verifier/pkg/testing/data"
	"github.com/stretchr/testify/assert"
)

func TestSignedEntityVerifierInitialization(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)

	// can't create a verifier without specifying either tlog or tsa
	_, err := NewSignedEntityVerifier(tr)
	assert.NotNil(t, err)

	// can create a verifier with both of them
	_, err = NewSignedEntityVerifier(tr, WithTransparencyLog(1), WithSignedTimestamps(1))
	assert.Nil(t, err)

	// unless we are really sure we want a verifier without either tlog or tsa
	_, err = NewSignedEntityVerifier(tr, WithoutAnyObserverTimestampsInsecure())
	assert.Nil(t, err)

	// can configure the verifiers with thresholds
	v, err := NewSignedEntityVerifier(tr, WithTransparencyLog(2), WithSignedTimestamps(10))

	assert.Nil(t, err)
	assert.Equal(t, 2, v.config.tlogEntriesThreshold)
	assert.Equal(t, 10, v.config.signedTimestampThreshold)

	// can't configure them with < 1 thresholds
	v, err = NewSignedEntityVerifier(tr, WithTransparencyLog(0), WithSignedTimestamps(-10))

	assert.Nil(t, err)
	assert.Equal(t, 1, v.config.tlogEntriesThreshold)
	assert.Equal(t, 1, v.config.signedTimestampThreshold)
}

// Testing a bundle:
// - signed by public good
// - one tlog entry
// - zero tsa entries

func TestEntitySignedByPublicGoodWithTlogVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := NewSignedEntityVerifier(tr, WithTransparencyLog(1))
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.Nil(t, err)
	assert.NotNil(t, res)

	assert.NotNil(t, res.Statement)
	assert.Equal(t, "https://slsa.dev/provenance/v1", res.Statement.PredicateType)
	assert.NotNil(t, res.Signature)
	assert.NotNil(t, res.Signature.Certificate)
	assert.Equal(t, "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main", res.Signature.Certificate.SubjectAlternativeName.Value)
	assert.NotEmpty(t, res.VerifiedTimestamps)
}

func TestEntitySignedByPublicGoodWithoutTimestampsVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := NewSignedEntityVerifier(tr, WithoutAnyObserverTimestampsInsecure())
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestEntitySignedByPublicGoodWithHighTlogThresholdFails(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := NewSignedEntityVerifier(tr, WithTransparencyLog(2))
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

func TestEntitySignedByPublicGoodExpectingTSAFails(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := NewSignedEntityVerifier(tr, WithTransparencyLog(1), WithSignedTimestamps(1))
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

// Now we test policy:

func TestEntitySignedByPublicGoodWithCertificateIdentityVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	goodCI, _ := certIDForTesting("", "", SigstoreSanRegex, ActionsIssuerValue, "")
	badCI, _ := certIDForTesting("BadSANValue", "", "", ActionsIssuerValue, "")

	v, err := NewSignedEntityVerifier(tr, WithTransparencyLog(1))

	assert.Nil(t, err)

	res, err := v.Verify(entity,
		WithCertificateIdentity(badCI),
		WithCertificateIdentity(goodCI))
	assert.Nil(t, err)

	assert.Equal(t, res.VerifiedIdentity.Issuer, ActionsIssuerValue)

	// but if only pass in the bad CI, it will fail:
	res, err = v.Verify(entity,
		WithCertificateIdentity(badCI))
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
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := NewSignedEntityVerifier(tr, WithTransparencyLog(1))
	assert.Nil(t, err)

	res, err := v.Verify(entity)
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
