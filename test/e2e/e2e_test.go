// Copyright 2025 The Sigstore Authors.
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

//go:build e2e

package e2e

import (
	"crypto/sha256"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

const (
	defaultCertID = "foo@bar.com"
)

var (
	artifactData = []byte("hello world")
	intotoData   = []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"hello_world.txt","digest":{"sha256":"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}}],"predicateType":"something","predicate":{}}`)
)

func TestSignVerify(t *testing.T) {
	opts := sign.BundleOptions{}

	trustedRootPath := os.Getenv("TRUSTED_ROOT")
	if trustedRootPath == "" {
		t.Fatal("must set TRUSTED_ROOT")
	}
	trustedRoot, err := root.NewTrustedRootFromPath(trustedRootPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.TrustedRoot = trustedRoot

	signingConfigPath := os.Getenv("SIGNING_CONFIG")
	if signingConfigPath == "" {
		t.Fatal("must set SIGNING_CONFIG")
	}
	signingConfig, err := root.NewSigningConfigFromPath(signingConfigPath)
	if err != nil {
		t.Fatal(err)
	}

	oidcURL := os.Getenv("OIDC_URL")
	if oidcURL == "" {
		t.Fatal("must set OIDC_URL")
	}
	token, err := getOIDCToken(oidcURL)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name               string
		content            sign.Content
		rekorVersion       uint32
		expectedTimestamps int
	}{
		{
			name: "hashedrekord_v001",
			content: &sign.PlainData{
				Data: artifactData,
			},
			rekorVersion:       1,
			expectedTimestamps: 2,
		},
		{
			name: "dsse_v001",
			content: &sign.DSSEData{
				Data:        intotoData,
				PayloadType: "application/vnd.in-toto+json",
			},
			rekorVersion:       1,
			expectedTimestamps: 2,
		},
		{
			name: "hashedrekor_v002",
			content: &sign.PlainData{
				Data: artifactData,
			},
			rekorVersion:       2,
			expectedTimestamps: 1,
		},
		{
			name: "dsse_v002",
			content: &sign.DSSEData{
				Data:        intotoData,
				PayloadType: "application/vnd.in-toto+json",
			},
			rekorVersion:       2,
			expectedTimestamps: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protoBundle, err := signContent(signingConfig, token, test.content, test.rekorVersion, opts)
			assert.NoError(t, err)

			result, err := verifyBundle(protoBundle, oidcURL, defaultCertID, getDigest(artifactData), trustedRoot)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotNil(t, result.Signature)
			assert.Len(t, result.VerifiedTimestamps, test.expectedTimestamps)
			assert.NotNil(t, result.VerifiedIdentity)
			assert.Equal(t, result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName, defaultCertID)
		})
	}
}

func signContent(signingConfig *root.SigningConfig, token string, content sign.Content, rekorVersion uint32, opts sign.BundleOptions) (*protobundle.Bundle, error) {
	rekorURLs, err := root.SelectServices(signingConfig.RekorLogURLs(), signingConfig.RekorLogURLsConfig(), []uint32{rekorVersion}, time.Now())
	if err != nil {
		return nil, err
	}
	for _, rekorURL := range rekorURLs {
		log.Printf("using Rekor URL %s", rekorURL)
		rekorOpts := &sign.RekorOptions{
			BaseURL: rekorURL,
			Timeout: time.Duration(90 * time.Second),
			Retries: 1,
			Version: rekorVersion,
		}
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
	}

	fulcioURL, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now())
	if err != nil {
		return nil, err
	}
	fulcioOpts := &sign.FulcioOptions{
		BaseURL: fulcioURL,
		Timeout: time.Duration(30 * time.Second),
		Retries: 1,
	}
	opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
	opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: token,
	}

	tsaURLs, err := root.SelectServices(signingConfig.TimestampAuthorityURLs(), signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now())
	if err != nil {
		return nil, err
	}
	for _, tsaURL := range tsaURLs {
		tsaOpts := &sign.TimestampAuthorityOptions{
			URL:     tsaURL,
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}

	return sign.Bundle(content, keypair, opts)
}

func verifyBundle(b *protobundle.Bundle, issuer, san string, digest []byte, trustedRoot root.TrustedMaterial) (*verify.VerificationResult, error) {
	bundleObj := bundle.Bundle{Bundle: b}

	verifierConfig := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}

	certID, err := verify.NewShortCertificateIdentity(issuer, "", san, "")
	if err != nil {
		return nil, err
	}
	identityPolicies := []verify.PolicyOption{verify.WithCertificateIdentity(certID)}
	artifactPolicy := verify.WithArtifactDigest("sha256", digest)

	signedEntityVerifier, err := verify.NewVerifier(trustedRoot, verifierConfig...)
	if err != nil {
		return nil, err
	}

	return signedEntityVerifier.Verify(&bundleObj, verify.NewPolicy(artifactPolicy, identityPolicies...))
}

func getDigest(artifact []byte) []byte {
	digest := sha256.Sum256(artifact)
	return digest[:]
}

// getOIDCToken gets an OIDC token from the mock OIDC server.
func getOIDCToken(issuer string) (string, error) {
	resp, err := http.Get(issuer + "/token")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
