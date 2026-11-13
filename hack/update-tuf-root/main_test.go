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
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func TestFetchInstanceUpdatesError(t *testing.T) {
	_, err := fetchInstanceUpdates(instanceUpdate{
		name:      "invalid",
		mirrorURL: tuf.DefaultMirror,
		rootBytes: []byte("not valid root json"),
		rootDest:  filepath.Join(t.TempDir(), "root.json"),
	})
	if err == nil {
		t.Fatal("expected error for invalid root bytes")
	}
}

func TestTargetValidators(t *testing.T) {
	trustedRootBytes, err := os.ReadFile(filepath.Join("..", "..", "examples", "trusted-root-public-good.json"))
	if err != nil {
		t.Fatalf("reading trusted-root-public-good.json: %v", err)
	}
	if _, err := root.NewTrustedRootFromJSON(trustedRootBytes); err != nil {
		t.Fatalf("validating trusted-root-public-good.json: %v", err)
	}
	if _, err := root.NewTrustedRootFromJSON([]byte("invalid json")); err == nil {
		t.Fatal("expected error for invalid trusted_root JSON")
	}

	signingConfigBytes, err := os.ReadFile(filepath.Join("..", "..", "examples", "signing_config.v0.2.json"))
	if err != nil {
		t.Fatalf("reading signing_config.v0.2.json: %v", err)
	}
	if _, err := root.NewSigningConfigFromJSON(signingConfigBytes); err != nil {
		t.Fatalf("validating signing_config.v0.2.json: %v", err)
	}
	if _, err := root.NewSigningConfigFromJSON([]byte("invalid json")); err == nil {
		t.Fatal("expected error for invalid signing_config JSON")
	}
}
