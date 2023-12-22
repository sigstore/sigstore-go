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

package tuf

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed repository
var embeddedRepo embed.FS

const DefaultMirror = "https://tuf-repo-cdn.sigstore.dev"

// Options represent the various options for a Sigstore TUF Client
type Options struct {
	// CacheValidity period in days (default 1)
	CacheValidity int
	// ForceCache controls if the cache should be used without update
	// as long as the metadata is valid
	ForceCache bool
	// Root is the TUF trust anchor
	Root []byte
	// CachePath is the location on disk for TUF cache
	// (default $HOME/.sigstore/tuf)
	CachePath string
	// RepositoryBaseURL is the TUF repository location URL
	// (default https://tuf-repo-cdn.sigstore.dev)
	RepositoryBaseURL string
	// DisableLocalCache mode allows a client to work on a read-only
	// files system if this is set, cache path is ignored.
	DisableLocalCache bool
}

// DefaultOptions returns an options struct for the public good instance
func DefaultOptions() *Options {
	var opts Options
	var err error

	opts.Root = DefaultRoot()
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to using a TUF repository in the temp location
		home = os.TempDir()
	}
	opts.CacheValidity = 1
	opts.CachePath = filepath.Join(home, ".sigstore", "root")
	opts.RepositoryBaseURL = DefaultMirror

	return &opts
}

// DefaultRoot returns the root.json for the public good instance
func DefaultRoot() []byte {
	var p = filepath.Join("repository", "root.json")

	b, err := embeddedRepo.ReadFile(p)
	if err != nil {
		// This should never happen.
		// ReadFile from an embedded FS will never fail as long as
		// the path is correct. If it fails, it would mean
		// that the binary is not assembled as it should, and there
		// is no way to recover from that.
		panic(err)
	}

	return b
}
