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

package data

import (
	_ "embed"
	"encoding/json"
	"os"
	"testing"

	"github.com/github/sigstore-go/pkg/bundle"
	"github.com/github/sigstore-go/pkg/root"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
)

// Unmarshal returns the Go value for the given bytes
func Unmarshal[T any](t *testing.T, data []byte) T {
	var v T
	err := json.Unmarshal(data, &v)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

//go:embed sigstoreBundle.json
var SigstoreBundleRaw []byte

//go:embed sigstore.js@2.0.0-provenanceBundle.json
var SigstoreJS200ProvenanceBundleRaw []byte

func TestBundle(t *testing.T, raw []byte) *bundle.ProtobufBundle {
	var b protobundle.Bundle
	err := protojson.Unmarshal(raw, &b)
	if err != nil {
		t.Fatal(err)
	}
	bun, err := bundle.NewProtobufBundle(&b)
	if err != nil {
		t.Fatal(err)
	}
	return bun
}

// SigstoreBundle returns a test *sigstore.Bundle
func SigstoreBundle(t *testing.T) *bundle.ProtobufBundle {
	return TestBundle(t, SigstoreBundleRaw)
}

func SigstoreJS200ProvenanceBundle(t *testing.T) *bundle.ProtobufBundle {
	return TestBundle(t, SigstoreJS200ProvenanceBundleRaw)
}

func PublicGoodTrustedMaterialRoot(t *testing.T) *root.TrustedRoot {
	trustedrootJSON, _ := os.ReadFile("../../examples/trusted-root-public-good.json")
	trustedRoot, _ := root.NewTrustedRootFromJSON(trustedrootJSON)

	assert.NotNil(t, trustedRoot)

	return trustedRoot
}
