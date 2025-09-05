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
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

var virtualSigstore *ca.VirtualSigstore
var virtualSigstoreOnce sync.Once
var virtualSigstoreErr error

func setupVirtualSigstore() {
	if virtualSigstore == nil {
		virtualSigstore, virtualSigstoreErr = ca.NewVirtualSigstore()
	}
}

func getFulcioResponse(detachedSct bool) (*http.Response, error) {
	virtualSigstoreOnce.Do(setupVirtualSigstore)
	if virtualSigstoreErr != nil {
		return nil, virtualSigstoreErr
	}

	leafCert, _, err := virtualSigstore.GenerateLeafCert("identity", "issuer")
	if err != nil {
		return nil, err
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	}))

	var responseStruct fulcioResponse
	if detachedSct {
		responseStruct = fulcioResponse{
			SignedCertificateDetachedSct: signedCertificateDetachedSct{
				Chain: chain{
					Certificates: []string{certPEM},
				},
			},
		}
	} else {
		responseStruct = fulcioResponse{
			SignedCertificateEmbeddedSct: signedCertificateEmbeddedSct{
				Chain: chain{
					Certificates: []string{certPEM},
				},
			},
		}
	}
	fulcioJSON, err := json.Marshal(responseStruct)
	if err != nil {
		return nil, err
	}

	response := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(fulcioJSON)),
	}

	return response, nil
}

type mockFulcio struct {
	detachedSct bool
}

func (m *mockFulcio) RoundTrip(_ *http.Request) (*http.Response, error) {
	return getFulcioResponse(m.detachedSct)
}

type failFirstFulcio struct {
	Count       int
	detachedSct bool
}

func (f *failFirstFulcio) RoundTrip(_ *http.Request) (*http.Response, error) {
	if f.Count <= 0 {
		f.Count++
		response := &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewReader([]byte(""))),
		}
		return response, nil
	}

	return getFulcioResponse(f.detachedSct)
}

func Test_GetCertificate(t *testing.T) {
	opts := &FulcioOptions{Retries: 1, Transport: &mockFulcio{}}
	fulcio := NewFulcio(opts)

	ctx := context.Background()
	keypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)

	// Test malformed idtoken
	certOpts := &CertificateProviderOptions{
		IDToken: "idtoken.notbase64.stuff",
	}
	cert, err := fulcio.GetCertificate(ctx, keypair, certOpts)
	assert.Nil(t, cert)
	assert.NotNil(t, err)

	// Test happy path
	certOpts.IDToken = "idtoken.eyJzdWIiOiJzdWJqZWN0In0K.stuff" // #nosec G101
	cert, err = fulcio.GetCertificate(ctx, keypair, certOpts)
	assert.NotNil(t, cert)
	assert.Nil(t, err)

	// Test successful retry
	roundTripper := &failFirstFulcio{}
	retryFulcioOpts := &FulcioOptions{Retries: 1, Transport: roundTripper}
	retryFulcio := NewFulcio(retryFulcioOpts)

	cert, err = retryFulcio.GetCertificate(ctx, keypair, certOpts)
	assert.NotNil(t, cert)
	assert.Nil(t, err)

	// Test unsuccessful retry
	roundTripper.Count = -1
	cert, err = retryFulcio.GetCertificate(ctx, keypair, certOpts)
	assert.Nil(t, cert)
	assert.NotNil(t, err)

	// Test detached SCT
	detachedOpts := &FulcioOptions{Retries: 1, Transport: &mockFulcio{detachedSct: true}}
	detachedFulcio := NewFulcio(detachedOpts)

	cert, err = detachedFulcio.GetCertificate(ctx, keypair, certOpts)
	assert.NotNil(t, cert)
	assert.NoError(t, err)

	t.Run("ed25519ph unsupported", func(t *testing.T) {
		// Test that Ed25519ph is rejected
		keypair, err := NewEphemeralKeypair(&EphemeralKeypairOptions{Algorithm: protocommon.PublicKeyDetails_PKIX_ED25519_PH})
		assert.Nil(t, err)
		certOpts.IDToken = "idtoken.eyJzdWIiOiJzdWJqZWN0In0K.stuff" // #nosec G101
		cert, err = fulcio.GetCertificate(ctx, keypair, certOpts)
		assert.Nil(t, cert)
		assert.ErrorContains(t, err, "ed25519ph unsupported by Fulcio")
	})
}
