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

package verify

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiHasher(t *testing.T) {
	testBytes := []byte("Hello, world!")
	hash256 := sha256.Sum256(testBytes)
	hash512 := sha512.Sum512(testBytes)

	hasher := newMultihasher([]crypto.Hash{crypto.SHA256, crypto.SHA512})
	_, err := hasher.Write(testBytes)
	assert.NoError(t, err)

	hashes := hasher.Sum(nil)

	assert.Equal(t, 2, len(hashes))
	assert.EqualValues(t, hash256[:], hashes[crypto.SHA256])
	assert.EqualValues(t, hash512[:], hashes[crypto.SHA512])
}
