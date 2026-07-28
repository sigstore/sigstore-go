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
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"crypto"
	"encoding/pem"
	"time"

	"filippo.io/mldsa"
	mldsax509 "filippo.io/mldsa/x509"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

var logKey = flag.String("log-key", "/Users/hblauzvern/development/rekor-tiles/tests/testdata/pki/mldsa-pub-key.pem", "Path to the transparency log ML-DSA public key")
var pubKey = flag.String("pub-key", "pubkey.pub", "Path to the artifact verification ML-DSA public key")
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

	var trustedMaterial root.TrustedMaterialCollection

	// Load the public key exported by the signing script if it exists
	pubKeyBytes, _ := os.ReadFile(*pubKey)
	tm := &mockTrustedMaterial{
		pubKeyBytes: pubKeyBytes,
		logKeyPath:  *logKey,
	}
	trustedMaterial = append(trustedMaterial, tm)

	verifier, err := verify.NewIdentityVerifier(trustedMaterial)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(*expectedIssuer, "", *expectedIdentity, "")
	if err != nil {
		return fmt.Errorf("failed to create certificate identity: %w", err)
	}

	pb := verify.NewPolicy(verify.WithArtifact(artifactFile), verify.WithCertificateIdentity(certID))

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

// mockTrustedMaterial implements root.TrustedMaterial to provide the public key for verification.
type mockTrustedMaterial struct {
	root.TrustedMaterialCollection
	pubKeyBytes []byte
	logKeyPath  string
}

func (m *mockTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	pemKey, err := os.ReadFile(m.logKeyPath)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil
	}
	pubKey, err := mldsax509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}

	return map[string]*root.TransparencyLog{
		"mock-rekor": {
			BaseURL:           "http://rekor-local",
			PublicKey:         pubKey,
			SignatureHashFunc: crypto.SHA256,
		},
	}
}

func (m *mockTrustedMaterial) PublicKeyVerifier(_ string) (root.TimeConstrainedVerifier, error) {
	if len(m.pubKeyBytes) == 0 {
		return nil, fmt.Errorf("public key not found")
	}

	// Parse the exported ML-DSA public key
	pubKey, err := mldsax509.ParsePKIXPublicKey(m.pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ML-DSA public key: %w", err)
	}

	return &mldsaVerifier{pubKey: pubKey.(*mldsa.PublicKey)}, nil
}

type mldsaVerifier struct {
	pubKey *mldsa.PublicKey
}

func (m *mldsaVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.pubKey, nil
}

func (m *mldsaVerifier) VerifySignature(sig, message io.Reader, _ ...signature.VerifyOption) error {
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return err
	}
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(m.pubKey, msgBytes, sigBytes, nil); err != nil {
		return fmt.Errorf("ML-DSA signature verification failed: %w", err)
	}
	return nil
}

func (m *mldsaVerifier) ValidAtTime(_ time.Time) bool {
	return true
}
