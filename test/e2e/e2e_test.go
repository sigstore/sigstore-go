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
	"crypto"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
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

	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		t.Fatal("must set ISSUER_URL")
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
		signingAlg         protocommon.PublicKeyDetails // Defaults to ECDSA P-256 SHA-256
		digestAlg          crypto.Hash
		useKey             bool
	}{
		{
			name: "hashedrekord_v001",
			content: &sign.PlainData{
				Data: artifactData,
			},
			digestAlg:          crypto.SHA256,
			rekorVersion:       1,
			expectedTimestamps: 2,
		},
		{
			name: "dsse_v001",
			content: &sign.DSSEData{
				Data:        intotoData,
				PayloadType: "application/vnd.in-toto+json",
			},
			digestAlg:          crypto.SHA256,
			rekorVersion:       1,
			expectedTimestamps: 2,
		},
		{
			name: "hashedrekor_v002",
			content: &sign.PlainData{
				Data: artifactData,
			},
			digestAlg:          crypto.SHA256,
			rekorVersion:       2,
			expectedTimestamps: 1,
		},
		{
			name: "hashedrekor_v002_key",
			content: &sign.PlainData{
				Data: artifactData,
			},
			digestAlg:          crypto.SHA256,
			rekorVersion:       2,
			expectedTimestamps: 1,
			useKey:             true,
		},
		{
			name: "hashedrekor_v002_ecdsa_p384",
			content: &sign.PlainData{
				Data: artifactData,
			},
			digestAlg:          crypto.SHA384,
			rekorVersion:       2,
			expectedTimestamps: 1,
			signingAlg:         protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
		},
		{
			name: "hashedrekor_v002_ed25519ph_key",
			content: &sign.PlainData{
				Data: artifactData,
			},
			digestAlg:          crypto.SHA512,
			rekorVersion:       2,
			expectedTimestamps: 1,
			signingAlg:         protocommon.PublicKeyDetails_PKIX_ED25519_PH,
			// when using ed25519, only self-managed keys are supported
			useKey: true,
		},
		{
			name: "dsse_v002",
			content: &sign.DSSEData{
				Data:        intotoData,
				PayloadType: "application/vnd.in-toto+json",
			},
			digestAlg:          crypto.SHA256,
			rekorVersion:       2,
			expectedTimestamps: 1,
		},
		{
			name: "dsse_v002_ed25519",
			content: &sign.DSSEData{
				Data:        intotoData,
				PayloadType: "application/vnd.in-toto+json",
			},
			digestAlg:          crypto.SHA256,
			rekorVersion:       2,
			expectedTimestamps: 1,
			signingAlg:         protocommon.PublicKeyDetails_PKIX_ED25519,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keypair, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{Algorithm: test.signingAlg})
			assert.NoError(t, err)
			if test.useKey {
				initTrustedRootWithKey(t, test.signingAlg, keypair.GetPublicKey(), &opts)
			}

			protoBundle, err := signContent(signingConfig, token, test.content, test.rekorVersion, keypair, test.useKey, opts)
			assert.NoError(t, err)

			result, err := verifyBundle(protoBundle, issuerURL, defaultCertID, getDigest(artifactData, test.digestAlg), test.useKey, opts.TrustedRoot)

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.NotNil(t, result.Signature)
			assert.Len(t, result.VerifiedTimestamps, test.expectedTimestamps)
			if !test.useKey {
				assert.NotNil(t, result.VerifiedIdentity)
				assert.Equal(t, result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName, defaultCertID)
			}
		})
	}
}

func signContent(signingConfig *root.SigningConfig, token string, content sign.Content, rekorVersion uint32, keypair sign.Keypair, useKey bool, opts sign.BundleOptions) (*protobundle.Bundle, error) {
	rekorServices, err := root.SelectServices(signingConfig.RekorLogURLs(), signingConfig.RekorLogURLsConfig(), []uint32{rekorVersion}, time.Now())
	if err != nil {
		return nil, err
	}
	for _, rekorService := range rekorServices {
		rekorOpts := &sign.RekorOptions{
			BaseURL: rekorService.URL,
			Timeout: time.Duration(90 * time.Second),
			Retries: 1,
			Version: rekorService.MajorAPIVersion,
		}
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
	}

	if !useKey {
		fulcioService, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now())
		if err != nil {
			return nil, err
		}
		fulcioOpts := &sign.FulcioOptions{
			BaseURL: fulcioService.URL,
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: token,
		}
	}

	tsaServices, err := root.SelectServices(signingConfig.TimestampAuthorityURLs(), signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now())
	if err != nil {
		return nil, err
	}
	for _, tsaService := range tsaServices {
		tsaOpts := &sign.TimestampAuthorityOptions{
			URL:     tsaService.URL,
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
	}

	return sign.Bundle(content, keypair, opts)
}

func verifyBundle(b *protobundle.Bundle, issuer, san string, digest []byte, useKey bool, trustedRoot root.TrustedMaterial) (*verify.VerificationResult, error) {
	bundleObj := bundle.Bundle{Bundle: b}

	verifierConfig := []verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	var identityPolicies []verify.PolicyOption

	if !useKey {
		verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))

		certID, err := verify.NewShortCertificateIdentity(issuer, "", san, "")
		if err != nil {
			return nil, err
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))
	} else {
		identityPolicies = append(identityPolicies, verify.WithKey())
	}

	artifactPolicy := verify.WithArtifactDigest("sha256", digest)

	signedEntityVerifier, err := verify.NewVerifier(trustedRoot, verifierConfig...)
	if err != nil {
		return nil, err
	}

	return signedEntityVerifier.Verify(&bundleObj, verify.NewPolicy(artifactPolicy, identityPolicies...))
}

func getDigest(artifact []byte, hf crypto.Hash) []byte {
	hasher := hf.New()
	hasher.Write(artifact)
	digest := hasher.Sum(nil)
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

func initTrustedRootWithKey(t *testing.T, alg protocommon.PublicKeyDetails, pubKey crypto.PublicKey, opts *sign.BundleOptions) {
	var defaultOpts []signature.LoadOption
	if alg == protocommon.PublicKeyDetails_PKIX_ED25519_PH {
		defaultOpts = []signature.LoadOption{options.WithED25519ph()}
	}
	verifier, err := signature.LoadDefaultVerifier(pubKey, defaultOpts...)
	assert.NoError(t, err)

	key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})
	keyTrustedMaterial := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return key, nil
	})
	trustedMaterial := &verifyTrustedMaterial{
		TrustedMaterial:    opts.TrustedRoot,
		keyTrustedMaterial: keyTrustedMaterial,
	}
	opts.TrustedRoot = trustedMaterial
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return v.keyTrustedMaterial.PublicKeyVerifier(hint)
}
