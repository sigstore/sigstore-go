// Copyright 2024 The Sigstore Authors.
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
	"log"
	"os"
	"time"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"
)

var idToken *string
var intoto *bool
var tsa *bool
var rekor *bool
var signingconfigPath string
var trustedrootPath string

func init() {
	idToken = flag.String("id-token", "", "OIDC token to send to Fulcio")
	intoto = flag.Bool("in-toto", false, "Content to sign is in-toto document")
	tsa = flag.Bool("tsa", false, "Include signed timestamp from timestamp authority")
	rekor = flag.Bool("rekor", false, "Including transparency log entry from Rekor")

	flag.StringVar(&signingconfigPath, "signing-config", "", "Path to signingconfig JSON file")
	flag.StringVar(&signingconfigPath, "s", "", "Path to signingconfig JSON file")

	flag.StringVar(&trustedrootPath, "trusted-root", "", "Path to trusted root JSON file")
	flag.StringVar(&trustedrootPath, "t", "", "Path to trusted root JSON file")

	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] FILE_TO_SIGN\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var content sign.Content

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	if *intoto {
		content = &sign.DSSEData{
			Data:        data,
			PayloadType: "application/vnd.in-toto+json",
		}
	} else {
		content = &sign.PlainData{
			Data: data,
		}
	}

	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyPem, err := keypair.GetPublicKeyPem()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Using public key:\n\n%s\n\n", publicKeyPem)

	opts := sign.BundleOptions{}

	var signingConfig *root.SigningConfig

	// A trusted root is not required but we will load one if
	// * it is given as argument or
	// * we are using default signing config (as in that case we know which trusted root to use)
	if trustedrootPath != "" {
		opts.TrustedRoot, err = root.NewTrustedRootFromPath(trustedrootPath)
		if err != nil {
			log.Fatal(err)
		}
	} else if signingconfigPath == "" {
		// Get staging trusted_root.json by default
		fetcher := fetcher.NewDefaultFetcher()
		fetcher.SetHTTPUserAgent(util.ConstructUserAgent())

		tufOptions := &tuf.Options{
			Root:              tuf.StagingRoot(),
			RepositoryBaseURL: tuf.StagingMirror,
			Fetcher:           fetcher,
		}
		tufClient, err := tuf.New(tufOptions)
		if err != nil {
			log.Fatal(err)
		}
		opts.TrustedRoot, err = root.GetTrustedRoot(tufClient)
		if err != nil {
			log.Fatal(err)
		}
	}

	if signingconfigPath != "" {
		signingConfig, err = root.NewSigningConfigFromPath(signingconfigPath)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// TODO: Uncomment once an updated v0.2 SigningConfig is distributed
		// via TUF
		// signingConfigPGI, err := root.GetSigningConfig(tufClient)

		// for now we hard code the staging services here
		signingConfig, err = root.NewSigningConfig(
			root.SigningConfigMediaType02,
			// Fulcio URLs
			[]root.Service{
				{
					URL:                 "https://fulcio.sigstage.dev",
					MajorAPIVersion:     1,
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				},
			},
			// OIDC Provider URLs
			[]root.Service{
				{
					URL:                 "https://oauth2.sigstage.dev/auth",
					MajorAPIVersion:     1,
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				},
			},
			// Rekor URLs
			[]root.Service{
				{
					URL:                 "https://rekor.sigstage.dev",
					MajorAPIVersion:     1,
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				},
			},
			root.ServiceConfiguration{
				Selector: v1.ServiceSelector_ANY,
			},
			[]root.Service{
				{
					URL:                 "https://timestamp.sigstage.dev/api/v1/timestamp",
					MajorAPIVersion:     1,
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				},
			},
			root.ServiceConfiguration{
				Selector: v1.ServiceSelector_ANY,
			},
		)
		if err != nil {
			log.Fatal(err)
		}
	}

	if *idToken != "" {
		fulcioURL, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		fulcioOpts := &sign.FulcioOptions{
			BaseURL: fulcioURL,
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: *idToken,
		}
	}

	if *tsa {
		tsaURLs, err := root.SelectServices(signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		for _, tsaURL := range tsaURLs {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL,
				Timeout: time.Duration(30 * time.Second),
				Retries: 1,
			}
			opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
		}
	}

	if *rekor {
		rekorURLs, err := root.SelectServices(signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(), []uint32{1}, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		for _, rekorURL := range rekorURLs {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL,
				Timeout: time.Duration(90 * time.Second),
				Retries: 1,
				Version: 1,
			}
			opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
		rekorURLs, err = root.SelectServices(signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(), []uint32{2}, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		for _, rekorURL := range rekorURLs {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL,
				Timeout: time.Duration(90 * time.Second),
				Retries: 1,
				Version: 2,
			}
			opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	bundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		log.Fatal(err)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bundleJSON))
}
