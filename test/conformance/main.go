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
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var bundlePath *string
var certOIDC *string
var certSAN *string
var identityToken *string
var staging = false
var trustedRootPath *string

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("\t%s sign-bundle --identity-token TOKEN --bundle FILE [--staging] FILE", os.Args[0])
	fmt.Printf("\t%s verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--trusted-root FILE] [--staging] FILE\n", os.Args[0])
}

func getTrustedRoot(staging bool) root.TrustedMaterial {
	var trustedRootJSON []byte
	var err error

	if trustedRootPath != nil {
		trustedRootJSON, err = os.ReadFile(*trustedRootPath)
	} else {
		opts := tuf.DefaultOptions()
		fetcher := fetcher.NewDefaultFetcher()
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
		opts.Fetcher = fetcher

		if staging {
			opts.Root = tuf.StagingRoot()
			opts.RepositoryBaseURL = tuf.StagingMirror
		}

		client, err := tuf.New(opts)
		if err != nil {
			log.Fatal(err)
		}
		trustedRootJSON, err = client.GetTarget("trusted_root.json")
		if err != nil {
			log.Fatal(err)
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		log.Fatal(err)
	}

	return tr
}

func parseArgs() {
	for i := 2; i < len(os.Args); {
		switch os.Args[i] {
		case "--bundle":
			bundlePath = &os.Args[i+1]
			i += 2
		case "--certificate-oidc-issuer":
			certOIDC = &os.Args[i+1]
			i += 2
		case "--certificate-identity":
			certSAN = &os.Args[i+1]
			i += 2
		case "--identity-token":
			identityToken = &os.Args[i+1]
			i += 2
		case "--staging":
			staging = true
			i++
		case "--trusted-root":
			trustedRootPath = &os.Args[i+1]
			i += 2
		default:
			i++
		}
	}
}

func signBundle(withRekor bool) (*protobundle.Bundle, error) {
	timeout := time.Duration(60 * time.Second)

	signingOptions := sign.BundleOptions{}

	instance := "sigstore"
	if staging {
		instance = "sigstage"
	}

	fulcioOpts := &sign.FulcioOptions{
		BaseURL: fmt.Sprintf("https://fulcio.%s.dev", instance),
		Timeout: timeout,
	}
	signingOptions.CertificateProvider = sign.NewFulcio(fulcioOpts)
	signingOptions.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: *identityToken,
	}

	if withRekor {
		rekorOpts := &sign.RekorOptions{
			BaseURL: fmt.Sprintf("https://rekor.%s.dev", instance),
			Timeout: timeout,
		}
		signingOptions.TransparencyLogs = append(signingOptions.TransparencyLogs, sign.NewRekor(rekorOpts))
	}

	if withRekor {
		// Verification will only work with Rekor
		signingOptions.TrustedRoot = getTrustedRoot(staging)
	}

	fileBytes, err := os.ReadFile(os.Args[len(os.Args)-1])
	if err != nil {
		return nil, err
	}
	content := &sign.PlainData{Data: fileBytes}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}

	bundle, err := sign.Bundle(content, keypair, signingOptions)
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	parseArgs()

	switch os.Args[1] {
	case "sign-bundle":
		bundle, err := signBundle(true)
		if err != nil {
			log.Fatal(err)
		}

		bundleBytes, err := protojson.Marshal(bundle)
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile(*bundlePath, bundleBytes, 0600)
		if err != nil {
			log.Fatal(err)
		}
	case "verify-bundle":
		// Load bundle
		b, err := bundle.LoadJSONFromPath(*bundlePath)
		if err != nil {
			log.Fatal(err)
		}

		var artifactPolicyOption verify.ArtifactPolicyOption
		fileOrDigest := os.Args[len(os.Args)-1]

		// Load digest or file
		if strings.Contains(fileOrDigest, ":") {
			algDigest := strings.Split(fileOrDigest, ":")
			alg, hexDigest := algDigest[0], algDigest[1]
			digest, err := hex.DecodeString(hexDigest)
			if err != nil {
				log.Fatal(err)
			}
			artifactPolicyOption = verify.WithArtifactDigest(alg, digest)
		} else {
			file, err := os.Open(fileOrDigest)
			if err != nil {
				log.Fatal(err)
			}
			artifactPolicyOption = verify.WithArtifact(file)
		}

		// Configure verification options
		identityPolicies := []verify.PolicyOption{}
		if *certOIDC != "" || *certSAN != "" {
			certID, err := verify.NewShortCertificateIdentity(*certOIDC, "", *certSAN, "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))
		}

		// Load trust root
		tr := getTrustedRoot(staging)

		verifierConfig := []verify.VerifierOption{}
		verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))

		// Check bundle and trusted root for signed timestamp information
		bundleTimestamps, err := b.Timestamps()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(tr.TimestampingAuthorities()) > 0 && len(bundleTimestamps) > 0 {
			verifierConfig = append(verifierConfig, verify.WithSignedTimestamps(1))
		}

		// Check bundle and trusted root for Tlog information
		if len(tr.RekorLogs()) > 0 {
			verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
			// Check for inclusion promise and integrated time
			if b.HasInclusionPromise() {
				verifierConfig = append(verifierConfig, verify.WithIntegratedTimestamps(1))
			}
		}

		sev, err := verify.NewVerifier(tr, verifierConfig...)
		if err != nil {
			log.Fatal(err)
		}

		// Verify bundle
		_, err = sev.Verify(b, verify.NewPolicy(artifactPolicyOption, identityPolicies...))
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("Unsupported command %s", os.Args[1])
	}
}
