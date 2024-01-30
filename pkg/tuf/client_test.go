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
	"testing"

	"github.com/stretchr/testify/assert"
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
