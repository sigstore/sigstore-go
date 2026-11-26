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
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	trustedRootPath  string
	pubKey           = flag.String("pub-key", "", "Path to the artifact verification ML-DSA-44 public key (PEM or DER)")
	expectedIssuer   = flag.String("expected-issuer", "", "Expected OIDC issuer for verification (required unless --pub-key is set)")
	expectedIdentity = flag.String("expected-identity", "", "Expected OIDC identity for verification (required unless --pub-key is set)")
)

func init() {
	flag.StringVar(&trustedRootPath, "trusted-root", "", "Path to trusted_root.json file (defaults to PQC staging TUF)")
	flag.StringVar(&trustedRootPath, "t", "", "Path to trusted_root.json file (defaults to PQC staging TUF)")
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] BUNDLE_FILE ARTIFACT_FILE\n", os.Args[0])
		flag.PrintDefaults()
		return fmt.Errorf("missing BUNDLE_FILE or ARTIFACT_FILE argument")
	}

	bundlePath := flag.Arg(0)
	artifactPath := flag.Arg(1)

	artifactFile, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to open artifact: %w", err)
	}
	defer artifactFile.Close()

	b, err := bundle.LoadJSONFromPathV2(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load bundle v2: %w", err)
	}

	var trustedRoot *root.TrustedRoot
	if trustedRootPath != "" {
		trustedRoot, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return fmt.Errorf("failed to load trusted root: %w", err)
		}
	} else {
		tufOpts := tuf.DefaultOptions().
			WithRoot(tuf.StagingPQCRoot()).
			WithRepositoryBaseURL(tuf.StagingPQCMirror)
		pqcTUFClient, err := tuf.New(tufOpts)
		if err != nil {
			return fmt.Errorf("failed to initialize PQC staging TUF client: %w", err)
		}
		trustedRoot, err = root.GetTrustedRoot(pqcTUFClient)
		if err != nil {
			return fmt.Errorf("failed to fetch trusted root from TUF: %w", err)
		}
	}

	trustedMaterial := root.TrustedMaterialCollection{trustedRoot}

	var policyOpt verify.PolicyOption
	if *pubKey != "" {
		pubKeyBytes, err := os.ReadFile(*pubKey)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}
		if pubBlock, _ := pem.Decode(pubKeyBytes); pubBlock != nil {
			pubKeyBytes = pubBlock.Bytes
		}
		parsedPubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
		pkVerifier, err := signature.LoadVerifier(parsedPubKey, crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("failed to load public key verifier: %w", err)
		}
		trustedMaterial = append(trustedMaterial, root.NewTrustedPublicKeyVerifiers(
			root.NewExpiringKey(pkVerifier, time.Time{}, time.Time{}),
		))
		policyOpt = verify.WithKey()
	} else {
		certID, err := verify.NewShortCertificateIdentity(*expectedIssuer, "", *expectedIdentity, "")
		if err != nil {
			return fmt.Errorf("failed to create certificate identity: %w", err)
		}
		policyOpt = verify.WithCertificateIdentity(certID)
	}

	verifier, err := verify.NewIdentityVerifier(trustedMaterial)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	pb := verify.NewPolicy(verify.WithArtifact(artifactFile), policyOpt)

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
