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
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Contains(t, r.Header.Get("User-Agent"), "custom-ua")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(tlogProofBytes)
	}))
	defer server.Close()

	// Pass URL with trailing slash to exercise URL joining
	client := NewIdentityRekorClient(
		server.URL+"/",
		WithIdentityRekorTimeout(5*time.Second),
		WithIdentityRekorRetries(1),
		WithIdentityRekorUserAgent("custom-ua"),
		WithIdentityRekorTransport(http.DefaultTransport),
	)
	cred := &OIDCCredential{Token: "test-token"}
	digest := sha256.Sum256([]byte("artifact"))
	req, err := cred.ToIdentityRequestV001(context.Background(), digest[:])
	require.NoError(t, err)

	pbProof, err := client.GetIdentityTransparencyLogEntry(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, pbProof)
	assert.Equal(t, tlogProofBytes, pbProof.Proof)
}

func TestIdentityRekorClient_ErrorHandling(t *testing.T) {
	statusCode := http.StatusInternalServerError
	respPayload := []byte("internal error")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode == http.StatusTemporaryRedirect {
			http.Redirect(w, r, "https://evil.example.com/steal", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(statusCode)
		_, _ = w.Write(respPayload)
	}))
	defer server.Close()

	client := NewIdentityRekorClient(server.URL)
	cred := &OIDCCredential{Token: "test-token"}
	digest := sha256.Sum256([]byte("artifact"))
	req, err := cred.ToIdentityRequestV001(context.Background(), digest[:])
	require.NoError(t, err)

	pbProof, err := client.GetIdentityTransparencyLogEntry(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code 500")
	assert.Nil(t, pbProof)

	// Redirects must not be followed
	statusCode = http.StatusTemporaryRedirect
	_, err = client.GetIdentityTransparencyLogEntry(context.Background(), req)
	assert.ErrorContains(t, err, "unexpected status code 307")

	// Scheme-less URL must be rejected
	schemeLessClient := NewIdentityRekorClient("rekor.sigstore.dev")
	_, err = schemeLessClient.GetIdentityTransparencyLogEntry(context.Background(), req)
	assert.ErrorContains(t, err, "base URL must include http:// or https:// scheme and host")

	// Malformed proof response on 201 Created
	statusCode = http.StatusCreated
	respPayload = []byte("not-a-valid-tlog-proof")
	_, err = client.GetIdentityTransparencyLogEntry(context.Background(), req)
	assert.ErrorContains(t, err, "failed to parse tlog proof")

	_, err = client.GetIdentityTransparencyLogEntry(context.Background(), nil)
	assert.ErrorContains(t, err, "request must not be nil")
}
