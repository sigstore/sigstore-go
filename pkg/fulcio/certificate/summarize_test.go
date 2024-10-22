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

package certificate_test

import (
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
	"github.com/stretchr/testify/assert"
)

func TestSummarizeCertificateWithActionsBundle(t *testing.T) {
	entity := data.SigstoreJS200ProvenanceBundle(t)

	vc, err := entity.VerificationContent()
	if err != nil {
		t.Fatalf("failed to get verification content: %v", err)
	}

	leaf := vc.GetLeafCertificate()

	if leaf == nil {
		t.Fatalf("expected verification content to be a certificate chain")
	}

	cs, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		t.Fatalf("failed to summarize: %v", err)
	}

	expected := certificate.Summary{
		CertificateIssuer:      "CN=sigstore-intermediate,O=sigstore.dev",
		SubjectAlternativeName: "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
		Extensions: certificate.Extensions{
			Issuer:                              "https://token.actions.githubusercontent.com",
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

	assert.Equal(t, expected, cs)
}

func TestSummarizeCertificateWithOauthBundle(t *testing.T) {
	entity := data.SigstoreBundle(t)

	vc, err := entity.VerificationContent()
	if err != nil {
		t.Fatalf("failed to get verification content: %v", err)
	}

	leaf := vc.GetLeafCertificate()

	if leaf == nil {
		t.Fatalf("expected verification content to be a certificate chain")
	}

	cs, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		t.Fatalf("failed to summarize: %v", err)
	}

	expected := certificate.Summary{
		CertificateIssuer:      "CN=sigstore-intermediate,O=sigstore.dev",
		SubjectAlternativeName: "brian@dehamer.com",
		Extensions: certificate.Extensions{
			Issuer: "https://github.com/login/oauth",
		},
	}

	assert.Equal(t, expected, cs)
}

func TestSummarizeCertificateWithOtherNameSAN(t *testing.T) {
	entity := data.OthernameBundle(t)
	vc, err := entity.VerificationContent()
	if err != nil {
		t.Fatalf("failed to get verification content: %v", err)
	}

	leaf := vc.GetLeafCertificate()

	if leaf == nil {
		t.Fatalf("expected verification content to be a certificate chain")
	}
	cs, err := certificate.SummarizeCertificate(leaf)
	assert.NoError(t, err)
	expected := certificate.Summary{
		CertificateIssuer:      "O=Linux Foundation,POSTALCODE=57274,STREET=548 Market St,L=San Francisco,ST=California,C=USA",
		SubjectAlternativeName: "foo!oidc.local",
		Extensions: certificate.Extensions{
			Issuer: "http://oidc.local:8080",
		},
	}
	assert.Equal(t, expected, cs)
}

func TestCompareExtensions(t *testing.T) {
	// Test that the extensions are equal
	actualExt := certificate.Extensions{
		Issuer:                   "https://token.actions.githubusercontent.com",
		GithubWorkflowTrigger:    "push",
		GithubWorkflowSHA:        "f0b49a04e5a62250e0f60fb128004a73110fe311",
		GithubWorkflowName:       "Release",
		GithubWorkflowRepository: "sigstore/sigstore-js",
		GithubWorkflowRef:        "refs/heads/main",
	}

	expectedExt := certificate.Extensions{
		Issuer: "https://token.actions.githubusercontent.com",
	}

	// Only the specified fields are expected to match
	assert.NoError(t, certificate.CompareExtensions(expectedExt, actualExt))

	// Blank fields are ignored
	expectedExt = certificate.Extensions{
		Issuer:             "https://token.actions.githubusercontent.com",
		GithubWorkflowName: "",
	}

	assert.NoError(t, certificate.CompareExtensions(expectedExt, actualExt))

	// but if any of the fields don't match, it should return false
	expectedExt = certificate.Extensions{
		Issuer:             "https://token.actions.githubusercontent.com",
		GithubWorkflowName: "Final",
	}

	errCompareExtensions := &certificate.ErrCompareExtensions{}
	assert.ErrorAs(t, certificate.CompareExtensions(expectedExt, actualExt), &errCompareExtensions)
	assert.Equal(t, errCompareExtensions.Error(), "expected GithubWorkflowName to be \"Final\", got \"Release\"")
}
