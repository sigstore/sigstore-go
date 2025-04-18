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

package sign

import (
	"context"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
)

func Test_EphemeralKeypair(t *testing.T) {
	opts := &EphemeralKeypairOptions{
		Hint: []byte("asdf"),
	}

	ctx := context.Background()
	ephemeralKeypair, err := NewEphemeralKeypair(opts)
	assert.NotNil(t, ephemeralKeypair)
	assert.Nil(t, err)

	hashAlgorithm := ephemeralKeypair.GetHashAlgorithm()
	assert.Equal(t, hashAlgorithm, protocommon.HashAlgorithm_SHA2_256)

	hint := ephemeralKeypair.GetHint()
	assert.Equal(t, hint, []byte("asdf"))

	keyAlgorithm := ephemeralKeypair.GetKeyAlgorithm()
	assert.Equal(t, keyAlgorithm, "ECDSA")

	pem, err := ephemeralKeypair.GetPublicKeyPem()
	assert.NotEqual(t, pem, "")
	assert.Nil(t, err)

	signature, digest, err := ephemeralKeypair.SignData(ctx, []byte("hello world"))
	assert.NotEqual(t, signature, "")
	assert.NotEqual(t, digest, "")
	assert.Nil(t, err)

	defaultEphemeralKeypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)
	hint = defaultEphemeralKeypair.GetHint()
	assert.NotEqual(t, hint, []byte(""))
}
