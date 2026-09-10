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
	"math"
	"net/http"
	"testing"

	"github.com/sigstore/sigstore/pkg/httpretry"
	"github.com/stretchr/testify/assert"
)

// disableBackoff removes the wait between retry attempts so tests that
// exercise the retry path do not sleep.
func disableBackoff(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	transport, ok := rt.(*httpretry.Transport)
	if !ok {
		t.Fatalf("expected *httpretry.Transport, got %T", rt)
	}
	transport.WaitMin = 0
	transport.WaitMax = 0
}

func Test_newRetryTransport(t *testing.T) {
	base := &mockFulcio{}
	transport := newRetryTransport(base, 3)
	assert.Equal(t, base, transport.Base)
	assert.Equal(t, 3, transport.MaxRetries)

	assert.Nil(t, newRetryTransport(nil, 0).Base)
	assert.Equal(t, 0, newRetryTransport(nil, 0).MaxRetries)
	assert.Equal(t, math.MaxInt, newRetryTransport(nil, math.MaxUint).MaxRetries)
}
