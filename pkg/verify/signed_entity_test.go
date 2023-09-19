package verify_test

import (
	"testing"
	"unicode"

	"encoding/json"

	"github.com/github/sigstore-verifier/pkg/fulcio/certificate"
	"github.com/github/sigstore-verifier/pkg/testing/data"
	v "github.com/github/sigstore-verifier/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestSignedEntityVerifierInitialization(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)

	// can't create a verifier without specifying either tlog or tsa
	_, err := v.NewSignedEntityVerifier(tr)
	assert.NotNil(t, err)

	// can create a verifier with both of them
	_, err = v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(1), v.WithSignedTimestamps(1))
	assert.Nil(t, err)

	// unless we are really sure we want a verifier without either tlog or tsa
	_, err = v.NewSignedEntityVerifier(tr, v.WithoutAnyObserverTimestampsInsecure())
	assert.Nil(t, err)

	// can configure the verifiers with thresholds
	_, err = v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(2), v.WithSignedTimestamps(10))

	assert.Nil(t, err)

	// can't configure them with < 1 thresholds
	_, err = v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(0), v.WithSignedTimestamps(-10))

	assert.Nil(t, err)
	// TODO: throw error
	// assert.Equal(t, 1, verifier.config.signedTimestampThreshold)
}

// Testing a bundle:
// - signed by public good
// - one tlog entry
// - zero tsa entries

func TestEntitySignedByPublicGoodWithTlogVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(1))
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

	v, err := v.NewSignedEntityVerifier(tr, v.WithoutAnyObserverTimestampsInsecure())
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestEntitySignedByPublicGoodWithHighTlogThresholdFails(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(2))
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

func TestEntitySignedByPublicGoodExpectingTSAFails(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(1), v.WithSignedTimestamps(1))
	assert.Nil(t, err)

	res, err := v.Verify(entity)
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

// Now we test policy:

func TestEntitySignedByPublicGoodWithCertificateIdentityVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	goodCI, _ := certIDForTesting("", "", v.SigstoreSanRegex, v.ActionsIssuerValue, "")
	badCI, _ := certIDForTesting("BadSANValue", "", "", v.ActionsIssuerValue, "")

	verifier, err := v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(1))

	assert.Nil(t, err)

	res, err := verifier.Verify(entity,
		v.WithCertificateIdentity(badCI),
		v.WithCertificateIdentity(goodCI))
	assert.Nil(t, err)

	assert.Equal(t, res.VerifiedIdentity.Issuer, v.ActionsIssuerValue)

	// but if only pass in the bad CI, it will fail:
	res, err = verifier.Verify(entity,
		v.WithCertificateIdentity(badCI))
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

	verifier, err := v.NewSignedEntityVerifier(tr, v.WithTransparencyLog(1))
	assert.Nil(t, err)

	res, err := verifier.Verify(entity)
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

// copied from verify/certificate_identity_test.go
func certIDForTesting(sanValue, sanType, sanRegex, issuer, runnerEnv string) (v.CertificateIdentity, error) {
	san, err := v.NewSANMatcher(sanValue, sanType, sanRegex)
	if err != nil {
		return v.CertificateIdentity{}, err
	}

	return v.CertificateIdentity{SubjectAlternativeName: san, Extensions: certificate.Extensions{Issuer: issuer, RunnerEnvironment: runnerEnv}}, nil
}
