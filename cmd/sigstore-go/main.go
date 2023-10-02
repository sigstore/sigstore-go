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

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

var artifact *string
var artifactDigest *string
var artifactDigestAlgorithm *string
var expectedOIDIssuer *string
var expectedSAN *string
var expectedSANRegex *string
var requireTSA *bool
var requireTlog *bool
var minBundleVersion *string
var onlineTlog *bool
var trustedPublicKey *string
var trustedrootJSONpath *string
var tufRootURL *string
var tufDirectory *string

func init() {
	artifact = flag.String("artifact", "", "Path to artifact to verify")
	artifactDigest = flag.String("artifact-digest", "", "Hex-encoded digest of artifact to verify")
	artifactDigestAlgorithm = flag.String("artifact-digest-algorithm", "sha256", "Digest algorithm")
	expectedOIDIssuer = flag.String("expectedIssuer", "", "The expected OIDC issuer for the signing certificate")
	expectedSAN = flag.String("expectedSAN", "", "The expected identity in the signing certificate's SAN extension")
	expectedSANRegex = flag.String("expectedSANRegex", "", "The expected identity in the signing certificate's SAN extension")
	requireTSA = flag.Bool("requireTSA", false, "Require RFC 3161 signed timestamp")
	requireTlog = flag.Bool("requireTlog", true, "Require Artifact Transparency log entry (Rekor)")
	minBundleVersion = flag.String("minBundleVersion", "", "Minimum acceptable bundle version (e.g. '0.1')")
	onlineTlog = flag.Bool("onlineTlog", false, "Verify Artifact Transparency log entry online (Rekor)")
	trustedPublicKey = flag.String("publicKey", "", "Path to trusted public key")
	trustedrootJSONpath = flag.String("trustedrootJSONpath", "examples/trusted-root-public-good.json", "Path to trustedroot JSON file")
	tufRootURL = flag.String("tufRootURL", "", "URL of TUF root containing trusted root JSON file")
	tufDirectory = flag.String("tufDirectory", "tufdata", "Directory to store TUF metadata")
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] BUNDLE_FILE ...\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	if err := run(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	b, err := bundle.LoadJSONFromPath(flag.Arg(0))
	if err != nil {
		return err
	}

	if *minBundleVersion != "" {
		if !b.MinVersion(*minBundleVersion) {
			return fmt.Errorf("bundle is not of minimum version %s", *minBundleVersion)
		}
	}

	verifierConfig := []verify.VerifierOption{}
	identityPolicies := []verify.PolicyOption{}
	var artifactPolicy verify.ArtifactPolicyOption

	verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))

	if *requireTSA {
		verifierConfig = append(verifierConfig, verify.WithSignedTimestamps(1))
	}

	if *requireTlog {
		verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
	}

	if *onlineTlog {
		verifierConfig = append(verifierConfig, verify.WithOnlineVerification())
	}

	if *expectedOIDIssuer != "" || *expectedSAN != "" || *expectedSANRegex != "" {
		certID, err := verify.NewShortCertificateIdentity(*expectedOIDIssuer, *expectedSAN, "", *expectedSANRegex)
		if err != nil {
			return err
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))
	}

	var trustedMaterial = make(root.TrustedMaterialCollection, 0)
	var trustedrootJSON []byte

	if *tufRootURL != "" {
		trustedrootJSON, err = tuf.GetTrustedrootJSON(*tufRootURL, *tufDirectory)
	} else if *trustedrootJSONpath != "" {
		trustedrootJSON, err = os.ReadFile(*trustedrootJSONpath)
	}
	if err != nil {
		return err
	}

	if len(trustedrootJSON) > 0 {
		var trustedRoot *root.TrustedRoot
		trustedRoot, err = root.NewTrustedRootFromJSON(trustedrootJSON)
		if err != nil {
			return err
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}
	if *trustedPublicKey != "" {
		pemBytes, err := os.ReadFile(*trustedPublicKey)
		if err != nil {
			return err
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return errors.New("failed to decode pem block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return err
		}
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(pubKey))
	}

	if len(trustedMaterial) == 0 {
		return errors.New("no trusted material provided")
	}

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return err
	}

	if *artifactDigest != "" {
		artifactDigestBytes, err := hex.DecodeString(*artifactDigest)
		if err != nil {
			return err
		}
		artifactPolicy = verify.WithArtifactDigest(*artifactDigestAlgorithm, artifactDigestBytes)
	}
	if *artifact != "" {
		file, err := os.Open(*artifact)
		if err != nil {
			return err
		}
		artifactPolicy = verify.WithArtifact(file)
	}

	res, err := sev.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Verification successful!\n")
	marshaled, err := json.MarshalIndent(res, "", "   ")
	if err != nil {
		return err
	}
	fmt.Println(string(marshaled))
	return nil
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}
