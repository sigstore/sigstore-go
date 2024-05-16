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
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Bundle(t *testing.T) {
	content := &PlainData{Data: []byte("qwerty")}
	opts := BundleOptions{}

	// Test requiring Keypair
	bundle, err := Bundle(content, nil, opts)
	assert.Nil(t, bundle)
	assert.NotNil(t, err)

	// Test minimal happy path
	keypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)
	bundle, err = Bundle(content, keypair, opts)
	assert.NotNil(t, bundle)
	assert.Nil(t, err)

	// Test requiring IDToken with Fulcio
	opts.Fulcio = NewFulcio(nil)
	bundle, err = Bundle(content, keypair, opts)
	assert.Nil(t, bundle)
	assert.NotNil(t, err)
}
