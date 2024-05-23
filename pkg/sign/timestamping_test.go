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
	"errors"
	"io"
	"testing"

	tsagenclient "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
	"github.com/stretchr/testify/assert"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

func getTSAResponse(params *tsagenclient.GetTimestampResponseParams, writer io.Writer) (*tsagenclient.GetTimestampResponseCreated, error) {
	var err error
	if virtualSigstore == nil {
		virtualSigstore, err = ca.NewVirtualSigstore()
		if err != nil {
			return nil, err
		}
	}

	req, err := io.ReadAll(params.Request)
	if err != nil {
		return nil, err
	}

	tsBytes, err := virtualSigstore.TimestampResponse(req)
	if err != nil {
		return nil, err
	}

	_, err = writer.Write(tsBytes)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

type mockTSAClient struct{}

func (m *mockTSAClient) GetTimestampResponse(params *tsagenclient.GetTimestampResponseParams, writer io.Writer, _ ...tsagenclient.ClientOption) (*tsagenclient.GetTimestampResponseCreated, error) {
	return getTSAResponse(params, writer)
}

type failFirstTSA struct {
	Count int
}

func (f *failFirstTSA) GetTimestampResponse(params *tsagenclient.GetTimestampResponseParams, writer io.Writer, _ ...tsagenclient.ClientOption) (*tsagenclient.GetTimestampResponseCreated, error) {
	if f.Count <= 0 {
		f.Count++
		return nil, errors.New("if at first you do not succeed")
	}

	return getTSAResponse(params, writer)
}

func Test_GetTimestamp(t *testing.T) {
	// Test happy path
	opts := &TimestampAuthorityOptions{Retries: 1, Client: &mockTSAClient{}}
	tsa := NewTimestampAuthority(opts)
	ctx := context.TODO()
	signature := []byte("somestuff")
	resp, err := tsa.GetTimestamp(ctx, signature)
	assert.NotNil(t, resp)
	assert.Nil(t, err)

	// Test successful retry
	failFirstClient := &failFirstTSA{}
	retryOpts := &TimestampAuthorityOptions{Retries: 1, Client: failFirstClient}
	retryTSA := NewTimestampAuthority(retryOpts)
	resp, err = retryTSA.GetTimestamp(ctx, signature)
	assert.NotNil(t, resp)
	assert.Nil(t, err)

	// Test unsuccessful retry
	failFirstClient.Count = -1
	resp, err = retryTSA.GetTimestamp(ctx, signature)
	assert.Nil(t, resp)
	assert.NotNil(t, err)
}
