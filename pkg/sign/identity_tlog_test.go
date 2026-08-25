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

package sign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/transparency-dev/formats/proof"
)

func TestIdentityRekorClient_Success(t *testing.T) {
	tlogProof := proof.TLogProof{
		Index:      1,
		Hashes:     [][32]byte{{}},
		Checkpoint: []byte("mock-checkpoint"),
		ExtraData:  []byte("issuer:https://example.com\nidentity:foo@bar.com"),
	}
	tlogProofBytes := tlogProof.Marshal()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2/log/entries", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(tlogProofBytes)
	}))
	defer server.Close()

	client := NewIdentityRekorClient(server.URL)
	cred := &OIDCCredential{Token: "test-token"}
	messageDigest := []byte("digest")

	pbProof, err := client.GetIdentityTransparencyLogEntry(context.Background(), cred, messageDigest)
	assert.NoError(t, err)
	assert.NotNil(t, pbProof)
	assert.Equal(t, tlogProofBytes, pbProof.Proof)
}

func TestIdentityRekorClient_ErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewIdentityRekorClient(server.URL)
	cred := &OIDCCredential{Token: "test-token"}
	messageDigest := []byte("digest")

	pbProof, err := client.GetIdentityTransparencyLogEntry(context.Background(), cred, messageDigest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code 500")
	assert.Nil(t, pbProof)
}
