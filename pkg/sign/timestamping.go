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
	"crypto"
	"crypto/sha256"
	"io"
	"time"

	"github.com/digitorus/timestamp"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	tsagenclient "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
)

type TimestampAuthorityOptions struct {
	BaseURL        string
	Timeout        time.Duration
	LibraryVersion string
}

type TimestampAuthority struct {
	options *TimestampAuthorityOptions
}

func NewTimestampAuthority(opts *TimestampAuthorityOptions) *TimestampAuthority {
	return &TimestampAuthority{
		options: opts,
	}
}

func (ta *TimestampAuthority) GetTimestamp(signature []byte) ([]byte, error) {
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

	client, err := tsaclient.GetTimestampClient(ta.options.BaseURL, tsaclient.WithUserAgent(constructUserAgent(ta.options.LibraryVersion)), tsaclient.WithContentType(tsaclient.TimestampQueryMediaType))
	if err != nil {
		return nil, err
	}

	clientParams := tsagenclient.NewGetTimestampResponseParams()
	if ta.options.Timeout != 0 {
		clientParams.SetTimeout(ta.options.Timeout)
	}
	clientParams.Request = io.NopCloser(bytes.NewReader(reqBytes))

	var respBytes bytes.Buffer
	_, err = client.Timestamp.GetTimestampResponse(clientParams, &respBytes)
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
