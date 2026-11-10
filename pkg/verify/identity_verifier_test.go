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

package verify

import (
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIdentityVerifier(t *testing.T) {
	_, err := NewIdentityVerifier(nil)
	assert.Error(t, err)

	tm := &root.BaseTrustedMaterial{}
	v, err := NewIdentityVerifier(tm)
	require.NoError(t, err)
	assert.NotNil(t, v)

	_, err = v.Verify(&BaseVerifiableEntity{}, NewPolicy(WithoutArtifactUnsafe(), WithoutIdentitiesUnsafe()))
	assert.ErrorIs(t, err, errNotImplemented)
}

func TestNewPKIVerifier(t *testing.T) {
	_, err := NewPKIVerifier(nil)
	assert.Error(t, err)

	tm := &root.BaseTrustedMaterial{}
	_, err = NewPKIVerifier(tm, WithPKISignedTimestamps(0))
	assert.Error(t, err)

	v, err := NewPKIVerifier(tm, WithPKISignedTimestamps(2))
	require.NoError(t, err)
	assert.Equal(t, 2, v.signedTimestampThreshold)

	_, err = v.Verify(&BaseVerifiableEntity{}, NewPolicy(WithoutArtifactUnsafe(), WithoutIdentitiesUnsafe()))
	assert.ErrorIs(t, err, errNotImplemented)
}

func TestNewKeyVerifier(t *testing.T) {
	_, err := NewKeyVerifier(nil)
	assert.Error(t, err)

	tm := &root.BaseTrustedMaterial{}
	vDefault, err := NewKeyVerifier(tm)
	require.NoError(t, err)
	assert.Equal(t, 0, vDefault.signedTimestampThreshold)

	_, err = NewKeyVerifier(tm, WithKeySignedTimestamps(0))
	assert.Error(t, err)

	vTS, err := NewKeyVerifier(tm, WithKeySignedTimestamps(1))
	require.NoError(t, err)
	assert.Equal(t, 1, vTS.signedTimestampThreshold)

	_, err = vTS.Verify(&BaseVerifiableEntity{}, NewPolicy(WithoutArtifactUnsafe(), WithKey()))
	assert.ErrorIs(t, err, errNotImplemented)
}
