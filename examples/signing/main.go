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

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

var Version string
var idToken *string
var intoto *bool

func init() {
	idToken = flag.String("id-token", "", "OIDC token to send to Fulcio")
	intoto = flag.Bool("in-toto", false, "Content to sign is in-toto document")
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
		content = sign.DSSEData{
			Data:        data,
			PayloadType: "application/vnd.in-toto+json",
		}
	} else {
		content = sign.PlainData{
			Data: data,
		}
	}

	var signer sign.Signer
	var keypair sign.Keypair

	if *idToken != "" {
		fulcioOpts := &sign.FulcioOptions{
			BaseURL:        "https://fulcio.sigstage.dev",
			IdentityToken:  *idToken,
			Timeout:        time.Duration(30 * time.Second),
			LibraryVersion: Version,
		}

		signer = sign.NewFulcio(fulcioOpts)
	} else {
		// Create a keypair to sign with
		var err error
		keypair, err = sign.NewEphemeralKeypair(nil)
		if err != nil {
			log.Fatal(err)
		}

		publicKeyPem, err := keypair.GetPublicKeyPem()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Using public key:\n\n%s\n\n", publicKeyPem)

		signer = &sign.KeySigner{}
	}

	bundle, err := signer.Sign(content, keypair)
	if err != nil {
		log.Fatal(err)
	}

	tsaOpts := &sign.TimestampAuthorityOptions{
		BaseURL:        "https://timestamp.githubapp.com",
		Timeout:        time.Duration(30 * time.Second),
		LibraryVersion: Version,
	}

	tsa := sign.NewTimestampAuthority(tsaOpts)
	err = tsa.GetTimestamp(bundle)
	if err != nil {
		log.Fatal(err)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bundleJSON))
}
