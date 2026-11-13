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

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

var logKey = flag.String("log-key", "", "Path to the transparency log ML-DSA public key")
var pubKey = flag.String("pub-key", "", "Path to the artifact verification ML-DSA public key")
var expectedIssuer = flag.String("expected-issuer", "http://fakeoidc:8080", "Expected OIDC issuer for verification")
var expectedIdentity = flag.String("expected-identity", "foo@bar.com", "Expected OIDC identity for verification")

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Printf("Usage: %s [OPTIONS] BUNDLE_FILE ARTIFACT_FILE\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *logKey == "" {
		return fmt.Errorf("--log-key is required")
	}

	bundlePath := flag.Arg(0)
	artifactPath := flag.Arg(1)

	artifactFile, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to open artifact: %w", err)
	}
	defer artifactFile.Close()

	// Load the Bundle V2
	b, err := bundle.LoadJSONFromPathV2(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load bundle v2: %w", err)
	}

	tm, err := newMockTrustedMaterial(*logKey, *pubKey)
	if err != nil {
		return err
	}

	verifier, err := verify.NewIdentityVerifier(tm)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	var policyOpt verify.PolicyOption
	if *pubKey != "" {
		policyOpt = verify.WithKey()
	} else {
		certID, err := verify.NewShortCertificateIdentity(*expectedIssuer, "", *expectedIdentity, "")
		if err != nil {
			return fmt.Errorf("failed to create certificate identity: %w", err)
		}
		policyOpt = verify.WithCertificateIdentity(certID)
	}

	pb := verify.NewPolicy(verify.WithArtifact(artifactFile), policyOpt)

	// Verify the bundle
	result, err := verifier.Verify(b, pb)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if result.Verified {
		fmt.Println("Transparent signature verified successfully!")
	} else {
		return fmt.Errorf("transparent signature verification failed")
	}
	return nil
}

// mockTrustedMaterial implements root.TrustedMaterial to provide the log and optional artifact public keys for verification.
type mockTrustedMaterial struct {
	root.BaseTrustedMaterial
	rekorLog  *root.TransparencyLog
	verifiers []root.TimeConstrainedVerifier
}

func newMockTrustedMaterial(logKeyPath, pubKeyPath string) (*mockTrustedMaterial, error) {
	pemKey, err := os.ReadFile(logKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read log public key: %w", err)
	}
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode log public key PEM")
	}
	logPubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log public key: %w", err)
	}

	tm := &mockTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:           "http://rekor-local",
			PublicKey:         logPubKey,
			SignatureHashFunc: crypto.SHA256,
		},
	}

	if pubKeyPath != "" {
		pubKeyBytes, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}
		if pubBlock, _ := pem.Decode(pubKeyBytes); pubBlock != nil {
			pubKeyBytes = pubBlock.Bytes
		}
		parsedPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		verifier, err := signature.LoadVerifier(parsedPubKey, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("failed to load public key verifier: %w", err)
		}
		tm.verifiers = []root.TimeConstrainedVerifier{
			root.NewExpiringKey(verifier, time.Time{}, time.Time{}),
		}
	}

	return tm, nil
}

func (m *mockTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{
		"mock-rekor": m.rekorLog,
	}
}

func (m *mockTrustedMaterial) PublicKeyVerifiers() []root.TimeConstrainedVerifier {
	return m.verifiers
}
