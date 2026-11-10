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
	"errors"
	"net/http"
	"time"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
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
	}
	return c
}

func (c *IdentityRekorClient) GetIdentityTransparencyLogEntry(_ context.Context, _ *pbrekor.IdentityRequestV001) (*bundleV2.TransparencyLogProof, error) {
	return nil, errors.New("not implemented")
}
