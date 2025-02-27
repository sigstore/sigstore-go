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

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
)

func TestMultiHasher(t *testing.T) {
	testBytes := []byte("Hello, world!")
	hash256 := sha256.Sum256(testBytes)
	hash384 := sha512.Sum384(testBytes)
	hash512 := sha512.Sum512(testBytes)

	for _, tc := range []struct {
		name   string
		hashes []crypto.Hash
		output map[crypto.Hash][]byte
		err    bool
	}{
		{
			name:   "one hash",
			hashes: []crypto.Hash{crypto.SHA256},
			output: map[crypto.Hash][]byte{
				crypto.SHA256: hash256[:],
			},
		},
		{
			name:   "two hashes",
			hashes: []crypto.Hash{crypto.SHA256, crypto.SHA512},
			output: map[crypto.Hash][]byte{
				crypto.SHA256: hash256[:],
				crypto.SHA512: hash512[:],
			},
		},
		{
			name:   "three hashes",
			hashes: []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512},
			output: map[crypto.Hash][]byte{
				crypto.SHA256: hash256[:],
				crypto.SHA384: hash384[:],
				crypto.SHA512: hash512[:],
			},
		},
		{
			name:   "no hashes",
			hashes: []crypto.Hash{},
			output: nil,
			err:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hasher, err := newMultihasher(tc.hashes)
			if tc.err {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			_, err = hasher.Write(testBytes)
			assert.NoError(t, err)

			hashes := hasher.Sum(nil)

			assert.EqualValues(t, tc.output, hashes)
			assert.Equal(t, len(tc.hashes), len(hashes))
			for _, hash := range tc.hashes {
				assert.EqualValues(t, tc.output[hash], hashes[hash])
			}
		})
	}
}

func makeStatement(subjectalgs [][]string) *in_toto.Statement {
	statement := &in_toto.Statement{
		Subject: make([]*in_toto.ResourceDescriptor, len(subjectalgs)),
	}
	for i, subjectAlg := range subjectalgs {
		statement.Subject[i] = &in_toto.ResourceDescriptor{
			Digest: make(map[string]string),
		}
		for _, digest := range subjectAlg {
			// content of digest doesn't matter for this test
			statement.Subject[i].Digest[digest] = "foobar"
		}
	}
	return statement
}

func TestGetHashFunctions(t *testing.T) {
	for _, test := range []struct {
		name         string
		algs         [][]string
		expectOutput []crypto.Hash
		expectError  bool
	}{
		{
			name:         "choose strongest algorithm",
			algs:         [][]string{{"sha256", "sha512"}},
			expectOutput: []crypto.Hash{crypto.SHA512},
		},
		{
			name:         "choose both algorithms",
			algs:         [][]string{{"sha256"}, {"sha512"}},
			expectOutput: []crypto.Hash{crypto.SHA256, crypto.SHA512},
		},
		{
			name:         "choose one algorithm",
			algs:         [][]string{{"sha512"}, {"sha256", "sha512"}},
			expectOutput: []crypto.Hash{crypto.SHA512},
		},
		{
			name:         "choose two algorithms",
			algs:         [][]string{{"sha256", "sha512"}, {"sha384", "sha512"}, {"sha256", "sha384"}},
			expectOutput: []crypto.Hash{crypto.SHA512, crypto.SHA384},
		},
		{
			name:         "ignore unknown algorithm",
			algs:         [][]string{{"md5", "sha512"}, {"sha256", "sha512"}},
			expectOutput: []crypto.Hash{crypto.SHA512},
		},
		{
			name:        "no recognized algorithms",
			algs:        [][]string{{"md5"}, {"sha1"}},
			expectError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			statement := makeStatement(test.algs)
			hfs, err := getHashFunctions(statement)
			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expectOutput, hfs)
		})
	}
}
