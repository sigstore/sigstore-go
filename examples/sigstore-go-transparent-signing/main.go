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
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	mldsax509 "filippo.io/mldsa/x509"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

var rekorAddr = flag.String("rekor-addr", "localhost:8080", "Address of the Identity Rekor service")
var identityToken = flag.String("identity-token", "", "OIDC identity token to use instead of a generated public key")

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Printf("Usage: %s [OPTIONS] FILE_TO_SIGN\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 1. Read the artifact to sign.
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	content := &sign.PlainData{
		Data: data,
	}

	var cred sign.IdentityCredential
	if *identityToken != "" {
		// Use provided OIDC token.
		cred = &sign.OIDCCredential{
			Token: *identityToken,
		}
	} else {
		// 2. Initialize an MLDSAKeypair.
		keypair, err := sign.NewMLDSAKeypair()
		if err != nil {
			log.Fatalf("failed to initialize MLDSAKeypair: %v", err)
		}

		// 3. Construct a PublicKeyCredential using the keypair.
		cred = &sign.PublicKeyCredential{
			Keypair: keypair,
		}

		// Export the public key for the verification example
		pubBytes, err := mldsax509.MarshalPKIXPublicKey(keypair.GetPublicKey())
		if err == nil {
			_ = os.WriteFile("pubkey.pub", pubBytes, 0600)
		}
	}

	// 4. Set up the IdentityRekorClient.
	tlogClient := sign.NewIdentityRekorClient(*rekorAddr)

	opts := sign.IdentityBundleOptions{
		Context:          context.Background(),
		TransparencyLogs: []sign.IdentityTransparencyLog{tlogClient},
	}

	// 5. Call IdentityBundle to sign a sample artifact and produce a V2 Bundle.
	bundle, err := sign.IdentityBundle(content, cred, opts)
	if err != nil {
		log.Fatalf("failed to create IdentityBundle: %v", err)
	}

	// 6. Print out or save the bundle.
	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		log.Fatalf("failed to marshal bundle to JSON: %v", err)
	}

	fmt.Println(string(bundleJSON))
}
