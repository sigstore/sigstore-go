// Copyright 2023 The Sigstore Authors.
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

package verify_test

import (
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestVerifyValidityPeriod(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	leaf, _, err := virtualSigstore.GenerateLeafCert("example@example.com", "issuer")
	assert.NoError(t, err)

	tests := []struct {
		name              string
		observerTimestamp time.Time
		wantErr           bool
	}{
		{
			name:              "before validity period",
			observerTimestamp: time.Now().Add(time.Hour * -24),
			wantErr:           true,
		},
		{
			name:              "inside validity period",
			observerTimestamp: time.Now(),
			wantErr:           false,
		},
		{
			name:              "after validity period",
			observerTimestamp: time.Now().Add(time.Hour * 24),
			wantErr:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verify.VerifyLeafCertificate(tt.observerTimestamp, leaf, virtualSigstore); (err != nil) != tt.wantErr {
				t.Errorf("VerifyLeafCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
