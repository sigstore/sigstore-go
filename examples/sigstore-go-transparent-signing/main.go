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
	"bytes"
	"context"
	"crypto"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/proof"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	pubKeyOut         = flag.String("pub-key-out", "", "Sign with a generated ML-DSA-44 keypair instead of interactive OIDC and write the PEM public key to this path")
	bundleOutPath     string
	signingConfigPath string
	trustedRootPath   string
)

func init() {
	flag.StringVar(&bundleOutPath, "out", "bundle.json", "Path to write the v2.0 bundle JSON (use \"-\" for stdout)")
	flag.StringVar(&bundleOutPath, "o", "bundle.json", "Path to write the v2.0 bundle JSON (use \"-\" for stdout)")
	flag.StringVar(&signingConfigPath, "signing-config", "", "Path to signing_config.v0.2.json file (defaults to PQC staging TUF)")
	flag.StringVar(&signingConfigPath, "s", "", "Path to signing_config.v0.2.json file (defaults to PQC staging TUF)")
	flag.StringVar(&trustedRootPath, "trusted-root", "", "Path to trusted_root.json file (defaults to PQC staging TUF when --signing-config is unset)")
	flag.StringVar(&trustedRootPath, "t", "", "Path to trusted_root.json file (defaults to PQC staging TUF when --signing-config is unset)")
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] FILE_TO_SIGN\n", os.Args[0])
		flag.PrintDefaults()
		return fmt.Errorf("missing FILE_TO_SIGN argument")
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		return fmt.Errorf("failed to read artifact: %w", err)
	}
	content := &sign.PlainData{Data: data}

	var pqcTUFClient *tuf.Client
	if signingConfigPath == "" {
		tufOpts := tuf.DefaultOptions().
			WithRoot(tuf.StagingPQCRoot()).
			WithRepositoryBaseURL(tuf.StagingPQCMirror)
		pqcTUFClient, err = tuf.New(tufOpts)
		if err != nil {
			return fmt.Errorf("failed to initialize PQC staging TUF client: %w", err)
		}
	}

	var signingConfig *root.SigningConfig
	if signingConfigPath != "" {
		signingConfig, err = root.NewSigningConfigFromPath(signingConfigPath)
		if err != nil {
			return fmt.Errorf("failed to load signing config: %w", err)
		}
	} else {
		signingConfig, err = root.GetSigningConfig(pqcTUFClient)
		if err != nil {
			return fmt.Errorf("failed to fetch signing config from TUF: %w", err)
		}
	}

	var trustedRoot root.TrustedMaterial
	if trustedRootPath != "" {
		trustedRoot, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return fmt.Errorf("failed to load trusted root: %w", err)
		}
	} else if signingConfigPath == "" {
		trustedRoot, err = root.GetTrustedRoot(pqcTUFClient)
		if err != nil {
			return fmt.Errorf("failed to fetch trusted root from TUF: %w", err)
		}
	}

	rekorServices, err := root.SelectServices(
		signingConfig.RekorLogURLs(),
		signingConfig.RekorLogURLsConfig(),
		sign.IdentityRekorAPIVersions,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to select identity transparency log: %w", err)
	}

	var (
		cred    sign.IdentityCredential
		keypair *sign.MLDSAKeypair
	)
	if *pubKeyOut != "" {
		keypair, err = sign.NewMLDSAKeypair()
		if err != nil {
			return fmt.Errorf("failed to initialize MLDSAKeypair: %w", err)
		}
		cred = &sign.PublicKeyCredential{Keypair: keypair}

		if trustedRoot != nil {
			verifier, err := signature.LoadVerifier(keypair.GetPublicKey(), crypto.Hash(0))
			if err != nil {
				return fmt.Errorf("failed to load public key verifier: %w", err)
			}
			trustedRoot = root.TrustedMaterialCollection{
				trustedRoot,
				root.NewTrustedPublicKeyVerifiers(root.NewExpiringKey(verifier, time.Time{}, time.Time{})),
			}
		}
	} else {
		oidcService, err := root.SelectService(signingConfig.OIDCProviderURLs(), []uint32{1}, time.Now())
		if err != nil {
			return fmt.Errorf("failed to select OIDC provider: %w", err)
		}
		tok, err := oauthflow.OIDConnect(oidcService.URL, "sigstore", "", "", oauthflow.DefaultIDTokenGetter)
		if err != nil {
			return fmt.Errorf("failed to fetch OIDC identity token: %w", err)
		}
		cred = &sign.OIDCCredential{Token: tok.RawString}
	}

	tlogClient := sign.NewIdentityRekorClient(rekorServices[0].URL, sign.WithIdentityRekorRetries(1))
	opts := sign.IdentityBundleOptions{
		Context:         context.Background(),
		TransparencyLog: tlogClient,
		TrustedRoot:     trustedRoot,
	}

	bundle, err := sign.IdentityBundle(content, cred, opts)
	if err != nil {
		return fmt.Errorf("failed to create IdentityBundle: %w", err)
	}

	if keypair != nil && *pubKeyOut != "" {
		pubPEM, err := keypair.GetPublicKeyPem()
		if err != nil {
			return fmt.Errorf("failed to marshal public key PEM: %w", err)
		}
		if err := os.WriteFile(*pubKeyOut, []byte(pubPEM), 0600); err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote public key to %s\n", *pubKeyOut)
	} else {
		var tlogProof proof.TLogProof
		if err := tlogProof.Unmarshal(bundle.GetVerificationMaterial().GetTransparencyLogProof().GetProof()); err == nil {
			for line := range bytes.SplitSeq(tlogProof.ExtraData, []byte("\n")) {
				if k, v, ok := strings.Cut(string(line), ":"); ok && (k == "issuer" || k == "identity") {
					fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
				}
			}
		}
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle to JSON: %w", err)
	}

	if bundleOutPath == "-" {
		fmt.Println(string(bundleJSON))
	} else {
		if err := os.WriteFile(bundleOutPath, append(bundleJSON, '\n'), 0600); err != nil {
			return fmt.Errorf("failed to write bundle: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote bundle to %s\n", bundleOutPath)
	}
	return nil
}
