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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/transparency-dev/formats/proof"
	"google.golang.org/protobuf/encoding/protojson"
)

type IdentityTransparencyLog interface {
	GetIdentityTransparencyLogEntry(ctx context.Context, cred IdentityCredential, messageDigest []byte) (*bundleV2.TlogProof, error)
}

// IdentityRekorClient is a wrapper around the Identity Rekor service.
type IdentityRekorClient struct {
	baseURL string
	client  *http.Client
}

func NewIdentityRekorClient(baseURL string) *IdentityRekorClient {
	return &IdentityRekorClient{
		baseURL: baseURL,
		client:  http.DefaultClient,
	}
}

func (c *IdentityRekorClient) GetIdentityTransparencyLogEntry(ctx context.Context, cred IdentityCredential, messageDigest []byte) (*bundleV2.TlogProof, error) {
	reqPb, err := cred.ToIdentityRequestV001(ctx, messageDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to create IdentityRequestV001: %w", err)
	}

	reqJSON, err := protojson.Marshal(reqPb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/api/v2/log/entries", c.baseURL)
	if !strings.HasPrefix(reqURL, "http://") && !strings.HasPrefix(reqURL, "https://") {
		reqURL = "http://" + reqURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req) // #nosec G704 -- Client controls the URL
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(b))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse using transparency-dev to validate
	var parsedProof proof.TLogProof
	if err := parsedProof.Unmarshal(respBody); err != nil {
		return nil, fmt.Errorf("failed to parse tlog proof: %w", err)
	}

	// Return standard pb proof
	return &bundleV2.TlogProof{
		Proof: respBody,
	}, nil
}
