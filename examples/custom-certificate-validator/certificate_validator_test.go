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

package main

import (
	"math/big"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestCRLWrapper(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	leaf, _, err := virtualSigstore.GenerateLeafCert("example@example.com", "issuer")
	assert.NoError(t, err)

	trustedMaterial := NewValidatingTrustedMaterial(virtualSigstore, []*big.Int{})
	validatingTrustedMaterial := NewValidatingTrustedMaterial(virtualSigstore, []*big.Int{leaf.SerialNumber})

	_, err = verify.VerifyLeafCertificate(time.Now(), leaf, trustedMaterial)
	assert.NoError(t, err)

	_, err = verify.VerifyLeafCertificate(time.Now(), leaf, validatingTrustedMaterial)
	assert.Error(t, err)
}
