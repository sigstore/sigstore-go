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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
)

var ctlog, fulcio, rekor, tsa *string

func init() {
	ctlog = flag.String("ctlog", "examples/construct-trusted-root/targets/ctlog.pem", "Ctlog public key file path")
	fulcio = flag.String("fulcio", "examples/construct-trusted-root/targets/fulcio.pem", "Fulcio certificate chain file path")
	rekor = flag.String("rekor", "examples/construct-trusted-root/targets/rekor.pem", "Rekor public key file path")
	tsa = flag.String("tsa", "examples/construct-trusted-root/targets/tsa-chain.pem", "TSA certificate chain file path")
	flag.Parse()
}

func readTarget(filePath *string, targetType string) (*root.BaseTrustedRootTarget, error) {
	if *filePath != "" {
		fulcioBytes, err := os.ReadFile(*filePath)
		if err != nil {
			return nil, fmt.Errorf("failed reading %s file: %w", targetType, err)
		}
		return &root.BaseTrustedRootTarget{
			Type:  targetType,
			Bytes: fulcioBytes,
		}, nil
	}

	return nil, nil
}

func main() {
	targets := []root.RawTrustedRootTarget{}

	ctlogTarget, err := readTarget(ctlog, root.CTFETarget)
	if err != nil {
		log.Fatal(err)
	}
	if ctlogTarget != nil {
		targets = append(targets, ctlogTarget)
	}

	fulcioTarget, err := readTarget(fulcio, root.FulcioTarget)
	if err != nil {
		log.Fatal(err)
	}
	if fulcioTarget != nil {
		targets = append(targets, fulcioTarget)
	}

	rekorTarget, err := readTarget(rekor, root.RekorTarget)
	if err != nil {
		log.Fatal(err)
	}
	if rekorTarget != nil {
		targets = append(targets, rekorTarget)
	}

	tsaTarget, err := readTarget(tsa, root.TSATarget)
	if err != nil {
		log.Fatal(err)
	}
	if tsaTarget != nil {
		targets = append(targets, tsaTarget)
	}

	trustedRoot, err := root.NewTrustedRootFromTargets(root.TrustedRootMediaType01, targets)
	if err != nil {
		log.Fatal(err)
	}

	serialized, err := json.Marshal(trustedRoot)
	if err != nil {
		log.Fatal(err)
	}

	var out bytes.Buffer
	err = json.Indent(&out, serialized, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out.String())
}
