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

package tuf

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/examples/repository/repository"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"golang.org/x/crypto/ed25519"
)

func TestNewOfflineClientFail(t *testing.T) {
	var opt = DefaultOptions()
	opt.WithForceCache().WithCachePath(t.TempDir())
	opt.WithRepositoryBaseURL("http://localhost:12345")

	// create a client, it should fail as it's set to forced cache,
	// and there is no metadata on disk, and the repository url is
	// invalid.

	c, err := New(opt)
	assert.Nil(t, c)
	assert.Error(t, err)
}

func TestRefresh(t *testing.T) {
	r := newTestRepo(t)
	r.AddTarget("foo", []byte("foo version 1"))
	rootJSON, err := r.roles.Root().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	var opt = DefaultOptions().
		WithRepositoryBaseURL("https://testing.local").
		WithRoot(rootJSON).
		WithCachePath(t.TempDir()).
		WithFetcher(r).
		WithDisableLocalCache()
	c, err := New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	target, err := c.GetTarget("foo")
	assert.NoError(t, err)
	assert.NotNil(t, target)
	assert.Equal(t, target, []byte("foo version 1"))

	r.AddTarget("foo", []byte("foo version 2"))
	assert.NoError(t, c.Refresh())

	target, err = c.GetTarget("foo")
	assert.NoError(t, err)
	assert.NotNil(t, target)
	assert.Equal(t, target, []byte("foo version 2"))
}

func TestInvalidRoot(t *testing.T) {
	r := newTestRepo(t)
	r2 := newTestRepo(t)
	rootJSON, err := r.roles.Root().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	// Create a client with a root that is not signed by the given repository fetcher
	var opt = DefaultOptions().
		WithRepositoryBaseURL("https://testing.local").
		WithRoot(rootJSON).
		WithCachePath(t.TempDir()).
		WithFetcher(r2).
		WithDisableLocalCache()
	c, err := New(opt)
	assert.Nil(t, c)
	assert.Error(t, err)
}

func TestInvalidRepositoryURL(t *testing.T) {
	var opt = DefaultOptions().
		WithRepositoryBaseURL(string(byte(0x7f))).
		WithCachePath(t.TempDir())
	c, err := New(opt)
	assert.Nil(t, c)
	assert.Error(t, err)
}

func TestCache(t *testing.T) {
	r := newTestRepo(t)
	r.AddTarget("foo", []byte("foo version 1"))
	rootJSON, err := r.roles.Root().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	var opt = DefaultOptions().
		WithRepositoryBaseURL("https://testing.local").
		WithRoot(rootJSON).
		WithCachePath(t.TempDir()).
		WithFetcher(r).
		WithCacheValidity(1)

	c, err := New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	target, err := c.GetTarget("foo")
	assert.NoError(t, err)
	assert.NotNil(t, target)
	assert.Equal(t, target, []byte("foo version 1"))

	r.AddTarget("foo", []byte("foo version 2"))

	// Create new client with the same cache path
	c, err = New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	target, err = c.GetTarget("foo")
	assert.NoError(t, err)
	assert.NotNil(t, target)
	// Cache is still valid, so we should get the old version
	assert.Equal(t, target, []byte("foo version 1"))

	// Set last updated time to 2 days ago, to trigger cache refresh
	cfg, err := LoadConfig(c.configPath())
	if err != nil {
		t.Fatal(err)
	}
	cfg.LastTimestamp = time.Now().Add(-48 * time.Hour)
	err = cfg.Persist(c.configPath())
	if err != nil {
		t.Fatal(err)
	}

	// Create new client with the same cache path
	c, err = New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	// Now we should get the new version
	target, err = c.GetTarget("foo")
	assert.NoError(t, err)
	assert.Equal(t, target, []byte("foo version 2"))

	r.AddTarget("foo", []byte("foo version 3"))

	// Delete config to show that client fetches fresh metadata when no config is present
	if err = os.Remove(c.configPath()); err != nil {
		t.Fatal(err)
	}

	// Create another new client with the same cache path
	c, err = New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	// Cache contains new version
	target, err = c.GetTarget("foo")
	assert.NoError(t, err)
	assert.Equal(t, target, []byte("foo version 3"))
}

func TestExpiredTimestamp(t *testing.T) {
	r := newTestRepo(t)
	r.AddTarget("foo", []byte("foo version 1"))
	rootJSON, err := r.roles.Root().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	var opt = DefaultOptions().
		WithRepositoryBaseURL("https://testing.local").
		WithRoot(rootJSON).
		WithCachePath(t.TempDir()).
		WithFetcher(r).
		WithCacheValidity(1)

	c, err := New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	target, err := c.GetTarget("foo")
	assert.NoError(t, err)
	assert.Equal(t, target, []byte("foo version 1"))

	r.AddTarget("foo", []byte("foo version 2"))

	opt.ForceCache = true
	c, err = New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	target, err = c.GetTarget("foo")
	assert.NoError(t, err)
	// Using ForceCache, so we should get the old version
	assert.Equal(t, target, []byte("foo version 1"))

	r.SetTimestamp(time.Now().Add(-1 * time.Second))

	// Manually write timestamp to disk, as Refresh() will fail
	err = r.roles.Timestamp().ToFile(filepath.Join(opt.CachePath, "testing.local", "timestamp.json"), false)
	if err != nil {
		t.Fatal(err)
	}

	// Client creation should fail as the timestamp is expired and the repository has an expired timestamp
	c, err = New(opt)
	assert.Nil(t, c)
	assert.Error(t, err)

	// Update repo with unexpired timestamp
	r.SetTimestamp(time.Now().AddDate(0, 0, 1))

	c, err = New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)

	target, err = c.GetTarget("foo")
	assert.NoError(t, err)
	// Even though ForceCache is set, we should get the new version since the cached timestamp is expired
	assert.Equal(t, target, []byte("foo version 2"))
}

// testRepo is a basic implementation of a TUF repository for testing purposes.
// It does not support delegates, multiple signers, thresholds, or other
// advanced TUF features, but it is sufficient for testing the sigstore-go
// client. Those other features should be covered by the go-tuf tests. This is
// primarily intended to test the caching and fetching behavior of the client.
type testRepo struct {
	keys  map[string]ed25519.PrivateKey
	roles *repository.Type
	dir   string
	t     *testing.T
}

func newTestRepo(t *testing.T) *testRepo {
	var err error
	r := &testRepo{
		keys:  make(map[string]ed25519.PrivateKey),
		roles: repository.New(),
		t:     t,
	}
	tomorrow := time.Now().AddDate(0, 0, 1).UTC()
	targets := metadata.Targets(tomorrow)
	r.roles.SetTargets(metadata.TARGETS, targets)
	r.dir, err = os.MkdirTemp("", "tuf-test-repo")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(filepath.Join(r.dir, metadata.TARGETS), 0700)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadata.Snapshot(tomorrow)
	r.roles.SetSnapshot(snapshot)
	timestamp := metadata.Timestamp(tomorrow)
	r.roles.SetTimestamp(timestamp)
	root := metadata.Root(tomorrow)
	r.roles.SetRoot(root)

	for _, name := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP, metadata.ROOT} {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		r.keys[name] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		err = r.roles.Root().Signed.AddKey(key, name)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range metadata.TOP_LEVEL_ROLE_NAMES {
		key := r.keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case metadata.TARGETS:
			_, err = r.roles.Targets(metadata.TARGETS).Sign(signer)
		case metadata.SNAPSHOT:
			_, err = r.roles.Snapshot().Sign(signer)
		case metadata.TIMESTAMP:
			_, err = r.roles.Timestamp().Sign(signer)
		case metadata.ROOT:
			_, err = r.roles.Root().Sign(signer)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	return r
}

// DownloadFile is a test implementation of the Fetcher interface, which the
// client may use to avoid making real HTTP requests. It returns the contents
// of the metadata files and target files in the test repository.
func (r *testRepo) DownloadFile(urlPath string, _ int64, _ time.Duration) ([]byte, error) {
	u, err := url.Parse(urlPath)
	if err != nil {
		return []byte{}, err
	}

	if strings.HasPrefix(u.Path, "/targets/") {
		re := regexp.MustCompile(`/targets/[0-9a-f]{64}\.(.*)$`)
		matches := re.FindStringSubmatch(u.Path)
		if len(matches) != 2 {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		targetFile, ok := r.roles.Targets(metadata.TARGETS).Signed.Targets[matches[1]]
		if !ok {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		data, err := os.ReadFile(targetFile.Path)
		if err != nil {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return data, nil
	}
	if u.Path == "/timestamp.json" {
		meta := r.roles.Timestamp()
		return meta.ToBytes(false)
	}
	re := regexp.MustCompile(`/(\d+)\.(root|snapshot|targets)\.json$`)
	matches := re.FindStringSubmatch(u.Path)
	if len(matches) != 3 {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: 404}
	}
	role := matches[2]
	version, err := strconv.Atoi(matches[1])
	if err != nil {
		return []byte{}, &metadata.ErrDownload{}
	}
	switch role {
	case metadata.ROOT:
		// TODO: handle all versions of signed root
		meta := r.roles.Root()
		if meta.Signed.Version != int64(version) {
			return []byte{}, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return meta.ToBytes(false)
	case metadata.SNAPSHOT:
		meta := r.roles.Snapshot()
		if meta.Signed.Version != int64(version) {
			return []byte{}, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return meta.ToBytes(false)
	case metadata.TARGETS:
		meta := r.roles.Targets(metadata.TARGETS)
		if meta.Signed.Version != int64(version) {
			return []byte{}, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return meta.ToBytes(false)
	}

	return []byte{}, nil
}

// AddTarget adds a target file to the repository. It also creates a new
// snapshot and timestamp metadata file, and signs them with the appropriate
// key.
func (r *testRepo) AddTarget(name string, content []byte) {
	targetHash := sha256.Sum256(content)
	localPath := filepath.Join(r.dir, metadata.TARGETS, fmt.Sprintf("%x.%s", targetHash, name))
	err := os.WriteFile(localPath, content, 0600)
	if err != nil {
		r.t.Fatal(err)
	}
	targetFileInfo, err := metadata.TargetFile().FromFile(localPath, "sha256")
	if err != nil {
		r.t.Fatal(err)
	}
	r.roles.Targets(metadata.TARGETS).Signed.Targets[name] = targetFileInfo
	r.roles.Targets("targets").Signed.Version++

	r.roles.Snapshot().Signed.Meta["targets.json"] = metadata.MetaFile(r.roles.Targets(metadata.TARGETS).Signed.Version)
	r.roles.Snapshot().Signed.Version++

	r.roles.Timestamp().Signed.Meta["snapshot.json"] = metadata.MetaFile(r.roles.Snapshot().Signed.Version)
	r.roles.Timestamp().Signed.Version++

	for _, name := range []string{metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		signer, err := signature.LoadSigner(r.keys[name], crypto.Hash(0))
		if err != nil {
			r.t.Fatal(err)
		}
		switch name {
		case metadata.TARGETS:
			r.roles.Targets(metadata.TARGETS).ClearSignatures()
			_, err = r.roles.Targets(metadata.TARGETS).Sign(signer)
		case metadata.SNAPSHOT:
			r.roles.Snapshot().ClearSignatures()
			_, err = r.roles.Snapshot().Sign(signer)
		case metadata.TIMESTAMP:
			r.roles.Timestamp().ClearSignatures()
			_, err = r.roles.Timestamp().Sign(signer)
		}
		if err != nil {
			r.t.Fatal(err)
		}
	}
}

// SetTimestamp sets the expiration date of the timestamp metadata file to the
// given date, and increments the version number. It then signs the metadata
// file with the appropriate key.
func (r *testRepo) SetTimestamp(date time.Time) {
	r.roles.Timestamp().Signed.Expires = date
	r.roles.Timestamp().Signed.Version++
	signer, err := signature.LoadSigner(r.keys[metadata.TIMESTAMP], crypto.Hash(0))
	if err != nil {
		r.t.Fatal(err)
	}
	r.roles.Timestamp().ClearSignatures()
	_, err = r.roles.Timestamp().Sign(signer)
	if err != nil {
		r.t.Fatal(err)
	}
}

func TestURLToPath(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "no-change",
			url:  "example.com",
			want: "example.com",
		},
		{
			name: "simple",
			url:  "https://example.com",
			want: "example.com",
		},
		{
			name: "simple with path",
			url:  "https://example.com/foo/bar",
			want: "example.com-foo-bar",
		},
		{
			name: "http scheme",
			url:  "http://example.com/foo/bar",
			want: "example.com-foo-bar",
		},
		{
			name: "different port",
			url:  "http://example.com:8080/foo/bar",
			want: "example.com-8080-foo-bar",
		},
		{
			name: "lowercase",
			url:  "http://EXAMPLE.COM:8080/foo/bar",
			want: "example.com-8080-foo-bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := URLToPath(tt.url); got != tt.want {
				t.Errorf("URLToPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
