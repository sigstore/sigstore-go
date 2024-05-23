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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

var virtualSigstore *ca.VirtualSigstore

func getFulcioResponse() (*http.Response, error) {
	var err error
	if virtualSigstore == nil {
		virtualSigstore, err = ca.NewVirtualSigstore()
		if err != nil {
			return nil, err
		}
	}

	leafCert, _, err := virtualSigstore.GenerateLeafCert("identity", "issuer")
	if err != nil {
		return nil, err
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	}))

	responseStruct := fulcioResponse{
		SctCertWithChain: signedCertificateEmbeddedSct{
			Chain: chain{
				Certificates: []string{certPEM},
			},
		},
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

type mockFulcioClient struct{}

func (m *mockFulcioClient) Do(_ *http.Request) (*http.Response, error) {
	return getFulcioResponse()
}

type failFirstFulcio struct {
	Count int
}

func (f *failFirstFulcio) Do(_ *http.Request) (*http.Response, error) {
	if f.Count <= 0 {
		f.Count++
		response := &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewReader([]byte(""))),
		}
		return response, nil
	}

	return getFulcioResponse()
}

func Test_GetCertificate(t *testing.T) {
	// Test happy path
	opts := &FulcioOptions{Retries: 1, Client: &mockFulcioClient{}}
	fulcio := NewFulcio(opts)

	ctx := context.TODO()
	keypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)

	idtoken := "idtoken.eyJzdWIiOiJzdWJqZWN0In0K.stuff" // #nosec G101

	cert, err := fulcio.GetCertificate(ctx, keypair, idtoken)
	assert.NotNil(t, cert)
	assert.Nil(t, err)

	// Test malformed idtoken
	cert, err = fulcio.GetCertificate(ctx, keypair, "idtoken.notbase64.stuff")
	assert.Nil(t, cert)
	assert.NotNil(t, err)

	// Test successful retry
	client := &failFirstFulcio{}
	retryFulcioOpts := &FulcioOptions{Retries: 1, Client: client}
	retryFulcio := NewFulcio(retryFulcioOpts)

	cert, err = retryFulcio.GetCertificate(ctx, keypair, idtoken)
	assert.NotNil(t, cert)
	assert.Nil(t, err)

	// Test unsuccessful retry
	client.Count = -1
	cert, err = retryFulcio.GetCertificate(ctx, keypair, idtoken)
	assert.Nil(t, cert)
	assert.NotNil(t, err)
}
