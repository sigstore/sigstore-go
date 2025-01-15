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

func init() {
	idToken = flag.String("id-token", "", "OIDC token to send to Fulcio")
	intoto = flag.Bool("in-toto", false, "Content to sign is in-toto document")
	tsa = flag.Bool("tsa", false, "Include signed timestamp from timestamp authority")
	rekor = flag.Bool("rekor", false, "Including transparency log entry from Rekor")
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

	// Get trusted_root.json
	fetcher := fetcher.DefaultFetcher{}
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())

	tufOptions := &tuf.Options{
		Root:              tuf.StagingRoot(),
		RepositoryBaseURL: tuf.StagingMirror,
		Fetcher:           &fetcher,
	}
	tufClient, err := tuf.New(tufOptions)
	if err != nil {
		log.Fatal(err)
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		log.Fatal(err)
	}

	signingConfigPGI, err := root.GetSigningConfig(tufClient)
	if err != nil {
		log.Fatal(err)
	}
	signingConfig := signingConfigPGI.AddTimestampAuthorityURLs("https://timestamp.githubapp.com/api/v1/timestamp")

	opts.TrustedRoot = trustedRoot

	if *idToken != "" {
		fulcioOpts := &sign.FulcioOptions{
			BaseURL: signingConfig.FulcioCertificateAuthorityURL(),
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		opts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: *idToken,
		}
	}

	if *tsa {
		for _, tsaURL := range signingConfig.TimestampAuthorityURLs() {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL,
				Timeout: time.Duration(30 * time.Second),
				Retries: 1,
			}
			opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
		}

		// staging TUF repo doesn't have accessible timestamp authorities
		opts.TrustedRoot = nil
	}

	if *rekor {
		for _, rekorURL := range signingConfig.RekorLogURLs() {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL,
				Timeout: time.Duration(90 * time.Second),
				Retries: 1,
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
