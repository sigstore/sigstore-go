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
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func getTSAResponse(req []byte) (*http.Response, error) {
	virtualSigstoreOnce.Do(setupVirtualSigstore)
	if virtualSigstoreErr != nil {
		return nil, virtualSigstoreErr
	}

	tsBytes, err := virtualSigstore.TimestampResponse(req)
	if err != nil {
		return nil, err
	}

	response := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(tsBytes)),
	}

	return response, nil
}

type mockTSAClient struct{}

func (m *mockTSAClient) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	return getTSAResponse(reqBytes)
}

type failFirstTSA struct {
	Count    int
	Attempts int
}

func (f *failFirstTSA) RoundTrip(req *http.Request) (*http.Response, error) {
	f.Attempts++
	if f.Count <= 0 {
		f.Count++
		response := &http.Response{
			StatusCode: 500,
			Body:       io.NopCloser(bytes.NewReader([]byte("internal error"))),
		}
		return response, nil
	}
	reqBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	return getTSAResponse(reqBytes)
}

// errorFirstTSA returns a transport error on the first attempt and succeeds
// afterwards. Reading the request body on the retry verifies that the body
// was replayed.
type errorFirstTSA struct {
	Attempts int
}

func (e *errorFirstTSA) RoundTrip(req *http.Request) (*http.Response, error) {
	e.Attempts++
	if e.Attempts == 1 {
		return nil, errors.New("connection reset by peer")
	}
	reqBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	return getTSAResponse(reqBytes)
}

func Test_GetTimestamp(t *testing.T) {
	// Test happy path
	opts := &TimestampAuthorityOptions{Retries: 1, Transport: &mockTSAClient{}}
	tsa := NewTimestampAuthority(opts)
	ctx := context.Background()
	signature := []byte("somestuff")
	resp, err := tsa.GetTimestamp(ctx, signature)
	assert.NotNil(t, resp)
	assert.Nil(t, err)

	// Test successful retry
	failFirstClient := &failFirstTSA{}
	retryOpts := &TimestampAuthorityOptions{Retries: 1, Transport: failFirstClient}
	retryTSA := NewTimestampAuthority(retryOpts)
	disableBackoff(t, retryTSA.client.Transport)
	resp, err = retryTSA.GetTimestamp(ctx, signature)
	assert.NotNil(t, resp)
	assert.Nil(t, err)
	assert.Equal(t, 2, failFirstClient.Attempts)

	// Test unsuccessful retry; the final response body is included in the error
	failFirstClient.Count = -1
	failFirstClient.Attempts = 0
	resp, err = retryTSA.GetTimestamp(ctx, signature)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "timestamp authority returned 500: internal error")
	assert.Equal(t, 2, failFirstClient.Attempts)

	// Test that transport errors are retried and the request body is replayed
	errorClient := &errorFirstTSA{}
	errorTSA := NewTimestampAuthority(&TimestampAuthorityOptions{Retries: 1, Transport: errorClient})
	disableBackoff(t, errorTSA.client.Transport)
	resp, err = errorTSA.GetTimestamp(ctx, signature)
	assert.NotNil(t, resp)
	assert.Nil(t, err)
	assert.Equal(t, 2, errorClient.Attempts)

	// Test that zero retries means a single attempt
	noRetryClient := &failFirstTSA{}
	noRetryTSA := NewTimestampAuthority(&TimestampAuthorityOptions{Retries: 0, Transport: noRetryClient})
	resp, err = noRetryTSA.GetTimestamp(ctx, signature)
	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "timestamp authority returned 500")
	assert.Equal(t, 1, noRetryClient.Attempts)
}
