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
	"crypto"
	"crypto/mldsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestDefaultInstances(t *testing.T) {
	instances := defaultInstances()
	if len(instances) != 3 {
		t.Fatalf("expected 3 default instances, got %d", len(instances))
	}
	wantNames := []string{"production", "staging", "pqc-staging"}
	for i, want := range wantNames {
		if instances[i].name != want {
			t.Fatalf("instance[%d].name = %q, want %q", i, instances[i].name, want)
		}
		if len(instances[i].rootBytes) == 0 {
			t.Fatalf("instance %q has empty rootBytes", want)
		}
		rootMeta, err := metadata.Root().FromBytes(instances[i].rootBytes)
		if err != nil {
			t.Fatalf("parsing embedded root for %q: %v", want, err)
		}
		if err := rootMeta.VerifyDelegate(metadata.ROOT, rootMeta); err != nil {
			t.Fatalf("verifying embedded self-signed root for %q: %v", want, err)
		}
	}
}

func TestFetchInstanceUpdatesMLDSA(t *testing.T) {
	tomorrow := time.Now().AddDate(0, 0, 1).UTC()
	roles := repository.New()
	roles.SetTargets(metadata.TARGETS, metadata.Targets(tomorrow))
	roles.SetSnapshot(metadata.Snapshot(tomorrow))
	roles.SetTimestamp(metadata.Timestamp(tomorrow))
	roles.SetRoot(metadata.Root(tomorrow))

	signers := make(map[string]signature.Signer)
	for _, name := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP, metadata.ROOT} {
		priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatal(err)
		}
		key, err := metadata.KeyFromPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := roles.Root().Signed.AddKey(key, name); err != nil {
			t.Fatal(err)
		}
		signer, err := signature.LoadSigner(priv, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		signers[name] = signer
	}

	if _, err := roles.Targets(metadata.TARGETS).Sign(signers[metadata.TARGETS]); err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Snapshot().Sign(signers[metadata.SNAPSHOT]); err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Timestamp().Sign(signers[metadata.TIMESTAMP]); err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Root().Sign(signers[metadata.ROOT]); err != nil {
		t.Fatal(err)
	}

	rootV1Bytes, err := roles.Root().ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate root to v2 with a new ML-DSA-44 root key co-signed by v1 and v2 keys.
	newRootPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	newRootKey, err := metadata.KeyFromPublicKey(newRootPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	newRootSigner, err := signature.LoadSigner(newRootPriv, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}

	roles.Root().Signed.Version = 2
	roles.Root().Signed.Roles[metadata.ROOT].KeyIDs = nil
	if err := roles.Root().Signed.AddKey(newRootKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	roles.Root().ClearSignatures()
	if _, err := roles.Root().Sign(signers[metadata.ROOT]); err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Root().Sign(newRootSigner); err != nil {
		t.Fatal(err)
	}
	rootV2Bytes, err := roles.Root().ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}

	targetsBytes, err := roles.Targets(metadata.TARGETS).ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := roles.Snapshot().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	timestampBytes, err := roles.Timestamp().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"/1.root.json":     rootV1Bytes,
		"/2.root.json":     rootV2Bytes,
		"/1.targets.json":  targetsBytes,
		"/1.snapshot.json": snapshotBytes,
		"/timestamp.json":  timestampBytes,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	destPath := filepath.Join(t.TempDir(), "pqc_staging_root.json")
	writes, err := fetchInstanceUpdates(instanceUpdate{
		name:      "pqc-staging-test",
		mirrorURL: srv.URL,
		rootBytes: rootV1Bytes,
		rootDest:  destPath,
	})
	if err != nil {
		t.Fatalf("fetchInstanceUpdates failed: %v", err)
	}
	if len(writes) != 1 {
		t.Fatalf("expected 1 pending write, got %d", len(writes))
	}
	if writes[0].destPath != destPath {
		t.Fatalf("destPath = %q, want %q", writes[0].destPath, destPath)
	}

	updatedRoot, err := metadata.Root().FromBytes(writes[0].data)
	if err != nil {
		t.Fatalf("parsing updated root: %v", err)
	}
	if updatedRoot.Signed.Version != 2 {
		t.Fatalf("expected updated root version 2, got %d", updatedRoot.Signed.Version)
	}
	if writes[0].data[len(writes[0].data)-1] != '\n' {
		t.Fatal(fmt.Errorf("expected trailing newline on updated root.json"))
	}
}

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
