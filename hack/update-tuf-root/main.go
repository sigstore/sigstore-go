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
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

type targetUpdate struct {
	targetName string
	destPath   string
	validate   func([]byte) error
}

type instanceUpdate struct {
	name      string
	mirrorURL string
	rootBytes []byte
	rootDest  string
	targets   []targetUpdate
}

type pendingWrite struct {
	destPath string
	data     []byte
}

func fetchInstanceUpdates(inst instanceUpdate) ([]pendingWrite, error) {
	tmpDir, err := os.MkdirTemp("", "sigstore-tuf-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	opts := tuf.DefaultOptions().
		WithRoot(inst.rootBytes).
		WithRepositoryBaseURL(inst.mirrorURL).
		WithCachePath(tmpDir)

	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("initializing TUF client for %s: %w", inst.name, err)
	}

	cachedRootPath := filepath.Join(tmpDir, tuf.URLToPath(inst.mirrorURL), "root.json")
	latestRoot, err := os.ReadFile(cachedRootPath) // #nosec G304 -- reading from temp TUF cache dir
	if err != nil {
		return nil, fmt.Errorf("reading cached root.json for %s: %w", inst.name, err)
	}

	// Ensure trailing newline for consistency with repository JSON files.
	if len(latestRoot) > 0 && latestRoot[len(latestRoot)-1] != '\n' {
		latestRoot = append(latestRoot, '\n')
	}

	// Verify the updated root.json can bootstrap a fresh TUF client on its own.
	verifyOpts := tuf.DefaultOptions().
		WithRoot(latestRoot).
		WithRepositoryBaseURL(inst.mirrorURL).
		WithDisableLocalCache()
	if _, err := tuf.New(verifyOpts); err != nil {
		return nil, fmt.Errorf("verifying refreshed root.json for %s: %w", inst.name, err)
	}

	writes := []pendingWrite{
		{
			destPath: inst.rootDest,
			data:     latestRoot,
		},
	}

	for _, t := range inst.targets {
		targetBytes, err := client.GetTarget(t.targetName)
		if err != nil {
			return nil, fmt.Errorf("fetching target %s from %s: %w", t.targetName, inst.name, err)
		}
		if t.validate != nil {
			if err := t.validate(targetBytes); err != nil {
				return nil, fmt.Errorf("validating target %s from %s: %w", t.targetName, inst.name, err)
			}
		}
		if len(targetBytes) > 0 && targetBytes[len(targetBytes)-1] != '\n' {
			targetBytes = append(targetBytes, '\n')
		}
		writes = append(writes, pendingWrite{
			destPath: t.destPath,
			data:     targetBytes,
		})
	}

	return writes, nil
}

func main() {
	instances := []instanceUpdate{
		{
			name:      "production",
			mirrorURL: tuf.DefaultMirror,
			rootBytes: tuf.DefaultRoot(),
			rootDest:  filepath.Join("pkg", "tuf", "repository", "root.json"),
			targets: []targetUpdate{
				{
					targetName: "trusted_root.json",
					destPath:   filepath.Join("examples", "trusted-root-public-good.json"),
					validate: func(b []byte) error {
						_, err := root.NewTrustedRootFromJSON(b)
						return err
					},
				},
				{
					targetName: "signing_config.v0.2.json",
					destPath:   filepath.Join("examples", "signing_config.v0.2.json"),
					validate: func(b []byte) error {
						_, err := root.NewSigningConfigFromJSON(b)
						return err
					},
				},
			},
		},
		{
			name:      "staging",
			mirrorURL: tuf.StagingMirror,
			rootBytes: tuf.StagingRoot(),
			rootDest:  filepath.Join("pkg", "tuf", "repository", "staging_root.json"),
		},
	}

	var allWrites []pendingWrite
	for _, inst := range instances {
		writes, err := fetchInstanceUpdates(inst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		allWrites = append(allWrites, writes...)
	}

	for _, w := range allWrites {
		cleanPath := filepath.Clean(w.destPath)
		if err := os.WriteFile(cleanPath, w.data, 0600); err != nil { // #nosec G304,G703 -- path is a fixed repo-relative path
			fmt.Fprintf(os.Stderr, "ERROR: writing %s: %v\n", cleanPath, err)
			os.Exit(1)
		}
	}
}
