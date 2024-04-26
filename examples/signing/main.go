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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

var Version string

func main() {
	flag.Parse()

	var signer sign.Signer

	if flag.NArg() == 0 {
		// Assume we're signing with a keypair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}

		// Print out privateKey.PublicKey() in PEM format
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal(err)
		}

		pemBlock := pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}
		fmt.Println(string(pem.EncodeToMemory(&pemBlock)))

		keypairOpts := &sign.KeypairOptions{
			Signer:        privateKey,
			HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKeyHint: []byte("someKeyHint"),
		}
		signer, err = sign.SignerKeypair(keypairOpts)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Assume arg is identity token for Fulcio
		fulcioOpts := &sign.FulcioOptions{
			BaseURL:        "https://fulcio.sigstage.dev",
			IdentityToken:  flag.Arg(0),
			Timeout:        time.Duration(30 * time.Second),
			LibraryVersion: Version,
		}

		signer = sign.SignerFulcio(fulcioOpts)
	}

	/*data := sign.PlainData{
		Data: []byte("hello world"),
	}*/

	data := sign.DSSEData{
		Data:        []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"hello_world.txt","digest":{"sha256":"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}}],"predicateType":"something","preidcate":{}}`),
		PayloadType: "application/vnd.in-toto+json",
	}

	bundle, err := signer.Sign(data)
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
