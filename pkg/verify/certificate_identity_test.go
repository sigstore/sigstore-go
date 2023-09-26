package verify

import (
	"testing"

	"github.com/github/sigstore-go/pkg/fulcio/certificate"
	"github.com/stretchr/testify/assert"
)

const (
	ActionsIssuerValue = "https://token.actions.githubusercontent.com"
	SigstoreSanValue   = "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
	SigstoreSanRegex   = "^https://github.com/sigstore/sigstore-js/"
)

func TestCertificateIdentityVerify(t *testing.T) {
	// given a certificate summary, it does what we expect

	actualCert := certificate.Summary{
		SubjectAlternativeName: certificate.SubjectAlternativeName{Type: "URI", Value: SigstoreSanValue},
		Extensions: certificate.Extensions{
			Issuer:                              ActionsIssuerValue,
			GithubWorkflowTrigger:               "push",
			GithubWorkflowSHA:                   "f0b49a04e5a62250e0f60fb128004a73110fe311",
			GithubWorkflowName:                  "Release",
			GithubWorkflowRepository:            "sigstore/sigstore-js",
			GithubWorkflowRef:                   "refs/heads/main",
			BuildSignerURI:                      "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
			BuildSignerDigest:                   "f0b49a04e5a62250e0f60fb128004a73110fe311",
			RunnerEnvironment:                   "github-hosted",
			SourceRepositoryURI:                 "https://github.com/sigstore/sigstore-js",
			SourceRepositoryDigest:              "f0b49a04e5a62250e0f60fb128004a73110fe311",
			SourceRepositoryRef:                 "refs/heads/main",
			SourceRepositoryIdentifier:          "495574555",
			SourceRepositoryOwnerURI:            "https://github.com/sigstore",
			SourceRepositoryOwnerIdentifier:     "71096353",
			BuildConfigURI:                      "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
			BuildConfigDigest:                   "f0b49a04e5a62250e0f60fb128004a73110fe311",
			BuildTrigger:                        "push",
			RunInvocationURI:                    "https://github.com/sigstore/sigstore-js/actions/runs/5904696764/attempts/1",
			SourceRepositoryVisibilityAtSigning: "public",
		},
	}

	// First, let's test happy paths:
	issuerOnlyID, _ := certIDForTesting("", "", "", ActionsIssuerValue, "")
	assert.True(t, issuerOnlyID.Verify(actualCert))

	sanValueOnly, _ := certIDForTesting(SigstoreSanValue, "", "", "", "")
	assert.True(t, sanValueOnly.Verify(actualCert))

	sanRegexOnly, _ := certIDForTesting("", "", SigstoreSanRegex, "", "")
	assert.True(t, sanRegexOnly.Verify(actualCert))

	// multiple values can be specified
	sanRegexAndIssuer, _ := certIDForTesting("", "", SigstoreSanRegex, ActionsIssuerValue, "github-hosted")
	assert.True(t, sanRegexAndIssuer.Verify(actualCert))

	// unhappy paths:
	// wrong issuer
	sanRegexAndWrongIssuer, _ := certIDForTesting("", "", SigstoreSanRegex, "https://token.actions.example.com", "")
	assert.False(t, sanRegexAndWrongIssuer.Verify(actualCert))

	// right san value, wrong san type
	sanValueAndWrongType, _ := certIDForTesting(SigstoreSanValue, "DNS", "", "", "")
	assert.False(t, sanValueAndWrongType.Verify(actualCert))

	// if we have an array of certIDs, only one needs to match
	ci, err := CertificateIdentities{sanRegexAndWrongIssuer, sanRegexAndIssuer}.Verify(actualCert)
	assert.Nil(t, err)
	assert.Equal(t, *ci, sanRegexAndIssuer)

	// if none match, we fail
	ci, err = CertificateIdentities{sanValueAndWrongType, sanRegexAndWrongIssuer}.Verify(actualCert)
	assert.NotNil(t, err)
	assert.Nil(t, ci)
}

func TestThatCertIDsHaveToHaveAnIssuer(t *testing.T) {
	_, err := NewShortCertificateIdentity("", "", "", "")
	assert.NotNil(t, err)

	_, err = NewShortCertificateIdentity("foobar", "", "", "")
	assert.Nil(t, err)
}

func certIDForTesting(sanValue, sanType, sanRegex, issuer, runnerEnv string) (CertificateIdentity, error) {
	san, err := NewSANMatcher(sanValue, sanType, sanRegex)
	if err != nil {
		return CertificateIdentity{}, err
	}

	return CertificateIdentity{SubjectAlternativeName: san, Extensions: certificate.Extensions{Issuer: issuer, RunnerEnvironment: runnerEnv}}, nil
}
