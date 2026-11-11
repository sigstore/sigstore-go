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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/transparency-dev/formats/proof"
	"google.golang.org/protobuf/encoding/protojson"
)

// IdentityTransparencyLog submits an identity request to a transparency log and returns its proof.
type IdentityTransparencyLog interface {
	// GetIdentityTransparencyLogEntry submits an IdentityRequestV001 to the log and returns a TransparencyLogProof.
	GetIdentityTransparencyLogEntry(ctx context.Context, req *pbrekor.IdentityRequestV001) (*bundleV2.TransparencyLogProof, error)
}

var _ IdentityTransparencyLog = (*IdentityRekorClient)(nil)

// IdentityRekorClient is a wrapper around the Identity Rekor service.
type IdentityRekorClient struct {
	baseURL   string
	client    *http.Client
	timeout   time.Duration
	retries   uint
	userAgent string
	transport http.RoundTripper
}

// IdentityRekorOption configures an IdentityRekorClient.
type IdentityRekorOption func(*IdentityRekorClient)

// WithIdentityRekorTimeout sets the HTTP request timeout for the IdentityRekorClient.
func WithIdentityRekorTimeout(timeout time.Duration) IdentityRekorOption {
	return func(c *IdentityRekorClient) {
		c.timeout = timeout
	}
}

// WithIdentityRekorRetries sets the number of retries for failed HTTP requests.
func WithIdentityRekorRetries(retries uint) IdentityRekorOption {
	return func(c *IdentityRekorClient) {
		c.retries = retries
	}
}

// WithIdentityRekorUserAgent sets an optional User-Agent prefix for requests.
func WithIdentityRekorUserAgent(ua string) IdentityRekorOption {
	return func(c *IdentityRekorClient) {
		c.userAgent = ua
	}
}

// WithIdentityRekorTransport sets a custom HTTP RoundTripper for requests.
func WithIdentityRekorTransport(transport http.RoundTripper) IdentityRekorOption {
	return func(c *IdentityRekorClient) {
		c.transport = transport
	}
}

// NewIdentityRekorClient creates a new IdentityRekorClient for the given base URL and options.
func NewIdentityRekorClient(baseURL string, opts ...IdentityRekorOption) *IdentityRekorClient {
	c := &IdentityRekorClient{
		baseURL: baseURL,
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	c.client = &http.Client{
		Timeout:   c.timeout,
		Transport: userAgentTransport{base: newRetryTransport(c.transport, c.retries), userAgent: userAgent(c.userAgent)},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c
}

// GetIdentityTransparencyLogEntry submits the IdentityRequestV001 to the Rekor v2 endpoint and returns the TransparencyLogProof.
func (c *IdentityRekorClient) GetIdentityTransparencyLogEntry(ctx context.Context, req *pbrekor.IdentityRequestV001) (*bundleV2.TransparencyLogProof, error) {
	if req == nil {
		return nil, errors.New("request must not be nil")
	}

	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("base URL must include http:// or https:// scheme and host")
	}
	reqURL, err := url.JoinPath(c.baseURL, "api/v2/log/entries")
	if err != nil {
		return nil, fmt.Errorf("failed to construct request URL: %w", err)
	}

	reqJSON, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq) // #nosec G704 -- Client controls the URL
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse using transparency-dev to validate
	var parsedProof proof.TLogProof
	if err := parsedProof.Unmarshal(respBody); err != nil {
		return nil, fmt.Errorf("failed to parse tlog proof: %w", err)
	}

	return &bundleV2.TransparencyLogProof{
		Proof: respBody,
	}, nil
}
