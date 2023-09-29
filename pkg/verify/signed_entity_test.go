package verify_test

import (
	"testing"
	"unicode"

	"encoding/json"

	"github.com/github/sigstore-go/pkg/fulcio/certificate"
	"github.com/github/sigstore-go/pkg/testing/data"
	"github.com/github/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestSignedEntityVerifierInitialization(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)

	// can't create a verifier without specifying either tlog or tsa
	_, err := verify.NewSignedEntityVerifier(tr)
	assert.NotNil(t, err)

	// can create a verifier with both of them
	_, err = verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.Nil(t, err)

	// unless we are really sure we want a verifier without either tlog or tsa
	_, err = verify.NewSignedEntityVerifier(tr, verify.WithoutAnyObserverTimestampsInsecure())
	assert.Nil(t, err)

	// can configure the verifiers with thresholds
	_, err = verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(2), verify.WithSignedTimestamps(10))

	assert.Nil(t, err)

	// can't configure them with < 1 thresholds
	_, err = verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(0), verify.WithSignedTimestamps(-10))
	assert.Error(t, err)
}

// Testing a bundle:
// - signed by public good
// - one tlog entry
// - zero tsa entries

func TestEntitySignedByPublicGoodWithTlogVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(1))
	assert.Nil(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
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

	v, err := verify.NewSignedEntityVerifier(tr, verify.WithoutAnyObserverTimestampsInsecure())
	assert.Nil(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestEntitySignedByPublicGoodWithHighTlogThresholdFails(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(2))
	assert.Nil(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

func TestEntitySignedByPublicGoodExpectingTSAFails(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	v, err := verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(1), verify.WithSignedTimestamps(1))
	assert.Nil(t, err)

	res, err := v.Verify(entity, SkipArtifactAndIdentitiesPolicy)
	assert.NotNil(t, err)
	assert.Nil(t, res)
}

// Now we test policy:

func TestEntitySignedByPublicGoodWithCertificateIdentityVerifiesSuccessfully(t *testing.T) {
	tr := data.PublicGoodTrustedMaterialRoot(t)
	entity := data.SigstoreJS200ProvenanceBundle(t)

	goodCI, _ := certIDForTesting("", "", verify.SigstoreSanRegex, verify.ActionsIssuerValue, "")
	badCI, _ := certIDForTesting("BadSANValue", "", "", verify.ActionsIssuerValue, "")

	verifier, err := verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(1))

	assert.Nil(t, err)

	res, err := verifier.Verify(entity,
		verify.NewPolicy(verify.WithoutArtifactUnsafe(),
			verify.WithCertificateIdentity(badCI),
			verify.WithCertificateIdentity(goodCI)))
	assert.Nil(t, err)

	assert.Equal(t, res.VerifiedIdentity.Issuer, verify.ActionsIssuerValue)

	// but if only pass in the bad CI, it will fail:
	res, err = verifier.Verify(entity,
		verify.NewPolicy(
			verify.WithoutArtifactUnsafe(),
			verify.WithCertificateIdentity(badCI)))
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

	verifier, err := verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(1))
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

// copied from verify/certificate_identity_test.go
func certIDForTesting(sanValue, sanType, sanRegex, issuer, runnerEnv string) (verify.CertificateIdentity, error) {
	san, err := verify.NewSANMatcher(sanValue, sanType, sanRegex)
	if err != nil {
		return verify.CertificateIdentity{}, err
	}

	return verify.CertificateIdentity{SubjectAlternativeName: san, Extensions: certificate.Extensions{Issuer: issuer, RunnerEnvironment: runnerEnv}}, nil
}
