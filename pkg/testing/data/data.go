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
	"embed"
	"path"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/assert"
)

//go:embed bundles/*.json trusted-roots/*.json
var embedded embed.FS

// Bundle reads a file from the embedded file system and returns a *bundle.Bundle
func Bundle(t *testing.T, filename string) (b *bundle.Bundle) {
	b = &bundle.Bundle{}
	data, err := embedded.ReadFile(path.Join("bundles", filename))
	assert.NoError(t, err)

	err = b.UnmarshalJSON(data)
	assert.NoError(t, err)

	return b
}

// TrustedRoot reads a file from the embedded file system and returns a *root.TrustedRoot
func TrustedRoot(t *testing.T, filename string) *root.TrustedRoot {
	data, err := embedded.ReadFile(path.Join("trusted-roots", filename))
	assert.NoError(t, err)

	trustedRoot, _ := root.NewTrustedRootFromJSON(data)
	assert.NoError(t, err)

	return trustedRoot
}
