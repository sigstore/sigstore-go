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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/repository"
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

func TestCreateClient(t *testing.T) {
	r := genTestRepo(t)

	rootJSON, err := r.roles.Root().ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	var opt = DefaultOptions().
		WithRepositoryBaseURL("https://testing.local").
		WithRoot(rootJSON).
		WithCachePath(t.TempDir()).
		WithFetcher(r)
	c, err := New(opt)
	assert.NotNil(t, c)
	assert.NoError(t, err)
}

type repo interface {
	Root() *metadata.Metadata[metadata.RootType]
	SetRoot(meta *metadata.Metadata[metadata.RootType])
	Snapshot() *metadata.Metadata[metadata.SnapshotType]
	SetSnapshot(meta *metadata.Metadata[metadata.SnapshotType])
	Timestamp() *metadata.Metadata[metadata.TimestampType]
	SetTimestamp(meta *metadata.Metadata[metadata.TimestampType])
	Targets(name string) *metadata.Metadata[metadata.TargetsType]
	SetTargets(name string, meta *metadata.Metadata[metadata.TargetsType])
}
type testrepo struct {
	keys  map[string]ed25519.PrivateKey
	roles repo
	dir   string
}

const (
	tufRoot      = "root"
	tufTargets   = "targets"
	tufSnapshot  = "snapshot"
	tufTimestamp = "timestamp"
)

func (r *testrepo) DownloadFile(urlPath string, _ int64, _ time.Duration) ([]byte, error) {
	u, err := url.Parse(urlPath)
	if err != nil {
		return []byte{}, err
	}

	if strings.HasPrefix(u.Path, "/targets/") {
		// TODO: handle targets
		return []byte{}, nil
	}
	if u.Path == "/timestamp.json" {
		meta := r.roles.Timestamp()
		return meta.ToBytes(false)
	}
	re := regexp.MustCompile(`/(\d+)\.(root|snapshot|targets)\.json$`)
	matches := re.FindStringSubmatch(u.Path)
	if len(matches) > 0 {
		role := matches[2]
		version, err := strconv.Atoi(matches[1])
		if err != nil {
			return []byte{}, metadata.ErrDownload{}
		}
		switch role {
		case tufRoot:
			meta := r.roles.Root()
			if meta.Signed.Version != int64(version) {
				return []byte{}, metadata.ErrDownloadHTTP{StatusCode: 404}
			}
			return meta.ToBytes(false)
		case tufSnapshot:
			meta := r.roles.Snapshot()
			if meta.Signed.Version != int64(version) {
				return []byte{}, metadata.ErrDownloadHTTP{StatusCode: 404}
			}
			return meta.ToBytes(false)
		case tufTargets:
			meta := r.roles.Targets(tufTargets)
			if meta.Signed.Version != int64(version) {
				return []byte{}, metadata.ErrDownloadHTTP{StatusCode: 404}
			}
			return meta.ToBytes(false)
		}
	}

	return []byte{}, nil
}

func genTestRepo(t *testing.T) *testrepo {
	var err error
	r := &testrepo{
		keys:  make(map[string]ed25519.PrivateKey),
		roles: repository.New(),
	}
	targets := metadata.Targets(helperExpireIn(7))
	r.roles.SetTargets(tufTargets, targets)
	r.dir, err = os.MkdirTemp("", "tuf-test-repo")
	if err != nil {
		t.Fatal(err)
	}
	err = os.Mkdir(filepath.Join(r.dir, tufTargets), 0700)
	if err != nil {
		t.Fatal(err)
	}
	targetPath := "foo"
	targetContent := []byte("foo 1")
	targetHash := sha256.Sum256(targetContent)
	localPath := filepath.Join(r.dir, tufTargets, fmt.Sprintf("%x.%s", targetHash, targetPath))
	err = os.WriteFile(localPath, targetContent, 0600)
	if err != nil {
		t.Fatal(err)
	}
	targetFileInfo, err := metadata.TargetFile().FromFile(localPath, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	r.roles.Targets(tufTargets).Signed.Targets[targetPath] = targetFileInfo
	snapshot := metadata.Snapshot(helperExpireIn(7))
	r.roles.SetSnapshot(snapshot)
	timestamp := metadata.Timestamp(helperExpireIn(1))
	r.roles.SetTimestamp(timestamp)
	root := metadata.Root(helperExpireIn(365))
	r.roles.SetRoot(root)

	for _, name := range []string{tufTargets, tufSnapshot, tufTimestamp, tufRoot} {
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

	for _, name := range []string{tufTargets, tufSnapshot, tufTimestamp, tufRoot} {
		key := r.keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		switch name {
		case tufTargets:
			_, err = r.roles.Targets(tufTargets).Sign(signer)
		case tufSnapshot:
			_, err = r.roles.Snapshot().Sign(signer)
		case tufTimestamp:
			_, err = r.roles.Timestamp().Sign(signer)
		case tufRoot:
			_, err = r.roles.Root().Sign(signer)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{tufTargets, tufSnapshot, tufTimestamp, tufRoot} {
		switch name {
		case tufTargets:
			filename := fmt.Sprintf("%d.%s.json", r.roles.Targets(tufTargets).Signed.Version, name)
			err = r.roles.Targets(tufTargets).ToFile(filepath.Join(r.dir, filename), true)
		case tufSnapshot:
			filename := fmt.Sprintf("%d.%s.json", r.roles.Snapshot().Signed.Version, name)
			err = r.roles.Snapshot().ToFile(filepath.Join(r.dir, filename), true)
		case tufTimestamp:
			filename := fmt.Sprintf("%s.json", name)
			err = r.roles.Timestamp().ToFile(filepath.Join(r.dir, filename), true)
		case tufRoot:
			filename := fmt.Sprintf("%d.%s.json", r.roles.Root().Signed.Version, name)
			err = r.roles.Root().ToFile(filepath.Join(r.dir, filename), true)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	return r
}

// helperExpireIn returns time offset by days
func helperExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}
