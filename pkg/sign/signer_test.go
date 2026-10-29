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
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
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

	pubKeyPem, err := keypair.GetPublicKeyPem()
	assert.NoError(t, err)
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pubKeyPem))
	assert.NoError(t, err)
	opts.TrustedRoot = trustedPublicKeyMaterial(pubKey)

	// Test signing and verification succeeds
	bundle, err = Bundle(content, keypair, opts)
	assert.NotNil(t, bundle)
	assert.Nil(t, err)
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

type ctxKey struct{}

// recordingTransport records the path, User-Agent and ctxKey context value of
// each request, then sends it with base (http.DefaultTransport if nil).
type recordingTransport struct {
	base       http.RoundTripper
	paths      []string
	userAgents []string
	values     []any
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.paths = append(r.paths, req.URL.Path)
	r.userAgents = append(r.userAgents, req.Header.Get("User-Agent"))
	r.values = append(r.values, req.Context().Value(ctxKey{}))
	if r.base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return r.base.RoundTrip(req)
}

func Test_BundleTransportAndContext(t *testing.T) {
	rekorV1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		created, err := (&mockRekor{}).CreateLogEntryContext(context.Background(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", created.ETag)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(created.Payload)
	}))
	defer rekorV1Server.Close()
	rekorV2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tle, err := (&mockRekorV2{}).Add(context.Background(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body, err := protojson.Marshal(tle)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	defer rekorV2Server.Close()

	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	content := &PlainData{Data: []byte("hello world")}

	t.Run("fulcio and tsa", func(t *testing.T) {
		fulcioTransport := &recordingTransport{base: &mockFulcio{}}
		tsaTransport := &recordingTransport{base: &mockTSAClient{}}
		keypair, err := NewEphemeralKeypair(nil)
		assert.NoError(t, err)

		_, err = Bundle(content, keypair, BundleOptions{
			CertificateProvider: NewFulcio(&FulcioOptions{BaseURL: "https://fulcio.example.com", Transport: fulcioTransport}),
			CertificateProviderOptions: &CertificateProviderOptions{
				IDToken: "idtoken.eyJzdWIiOiJzdWJqZWN0In0K.stuff", // #nosec G101
			},
			TimestampAuthorities: []*TimestampAuthority{NewTimestampAuthority(&TimestampAuthorityOptions{URL: "https://tsa.example.com/api/v1/timestamp", Transport: tsaTransport})},
			Context:              ctx,
		})
		assert.NoError(t, err)
		assert.Equal(t, []string{"/api/v2/signingCert"}, fulcioTransport.paths)
		assert.Equal(t, []any{"caller"}, fulcioTransport.values)
		assert.Equal(t, []string{"/api/v1/timestamp"}, tsaTransport.paths)
		assert.Equal(t, []any{"caller"}, tsaTransport.values)
	})

	for _, tc := range []struct {
		name      string
		url       string
		version   uint32
		entryPath string
	}{
		{"rekor v1", rekorV1Server.URL, rekorV1, "/api/v1/log/entries"},
		{"rekor v2", rekorV2Server.URL, rekorV2, "/api/v2/log/entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rekorTransport := &recordingTransport{}
			keypair, err := NewEphemeralKeypair(nil)
			assert.NoError(t, err)

			_, err = Bundle(content, keypair, BundleOptions{
				TransparencyLogs: []Transparency{NewRekor(&RekorOptions{BaseURL: tc.url, Version: tc.version, Transport: rekorTransport})},
				Context:          ctx,
			})
			assert.NoError(t, err)
			assert.Equal(t, []string{tc.entryPath}, rekorTransport.paths)
			assert.Equal(t, []string{userAgent("")}, rekorTransport.userAgents)
			assert.Equal(t, []any{"caller"}, rekorTransport.values)
		})
	}
}
