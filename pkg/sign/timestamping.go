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
	"crypto"
	"crypto/sha256"
	"io"
	"math"
	"time"

	"github.com/digitorus/timestamp"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	tsagenclient "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
)

type TSAClient interface {
	GetTimestampResponse(params *tsagenclient.GetTimestampResponseParams, writer io.Writer, opts ...tsagenclient.ClientOption) (*tsagenclient.GetTimestampResponseCreated, error)
}

type TimestampAuthorityOptions struct {
	// URL of Timestamp Authority instance
	URL string
	// Optional timeout for network requests (default 30s; use negative value for no timeout)
	Timeout time.Duration
	// Optional number of times to retry on HTTP 5XX
	Retries uint
	// Optional version string for user agent
	LibraryVersion string
	// Optional client (for dependency injection)
	Client TSAClient
}

type TimestampAuthority struct {
	options *TimestampAuthorityOptions
}

func NewTimestampAuthority(opts *TimestampAuthorityOptions) *TimestampAuthority {
	return &TimestampAuthority{options: opts}
}

func (ta *TimestampAuthority) GetTimestamp(ctx context.Context, signature []byte) ([]byte, error) {
	signatureHash := sha256.Sum256(signature)

	req := &timestamp.Request{
		Certificates:  true,
		HashAlgorithm: crypto.SHA256,
		HashedMessage: signatureHash[:],
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	if ta.options.Client == nil {
		client, err := tsaclient.GetTimestampClient(ta.options.URL, tsaclient.WithUserAgent(constructUserAgent(ta.options.LibraryVersion)), tsaclient.WithContentType(tsaclient.TimestampQueryMediaType))
		if err != nil {
			return nil, err
		}
		ta.options.Client = client.Timestamp
	}

	attempts := uint(0)
	var respBytes bytes.Buffer

	for attempts <= ta.options.Retries {
		clientParams := tsagenclient.NewGetTimestampResponseParams()
		if ta.options.Timeout >= 0 {
			if ta.options.Timeout == 0 {
				ta.options.Timeout = 30 * time.Second
			}
			clientParams.SetTimeout(ta.options.Timeout)
		}
		clientParams.Request = io.NopCloser(bytes.NewReader(reqBytes))

		_, err = ta.options.Client.GetTimestampResponse(clientParams, &respBytes)
		if err == nil && attempts > 0 {
			break
		}

		respBytes.Reset()
		delay := time.Duration(math.Pow(2, float64(attempts)))
		timer := time.NewTimer(delay * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		attempts++
	}

	if err != nil {
		return nil, err
	}

	_, err = timestamp.ParseResponse(respBytes.Bytes())
	if err != nil {
		return nil, err
	}

	return respBytes.Bytes(), nil
}

func constructUserAgent(version string) string {
	userAgent := "sigstore-go"
	if version != "" {
		userAgent += "/"
		userAgent += version
	}

	return userAgent
}
