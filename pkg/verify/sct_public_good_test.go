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

package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctLogOverride replaces the CT logs of the wrapped TrustedMaterial.
type ctLogOverride struct {
	root.TrustedMaterial
	ctLogs map[string]*root.TransparencyLog
}

func (o *ctLogOverride) CTLogs() map[string]*root.TransparencyLog {
	return o.ctLogs
}

// TestVerifySignedCertificateTimestampPublicGoodCertificate verifies an SCT
// that the public good CT log issued for a Fulcio certificate. Unlike the
// tests in sct_test.go, neither the certificate nor the SCT signature were
// produced by this repository, so this checks the SCT parsing, SCT list
// removal, and signature input encoding against an independent
// implementation.
func TestVerifySignedCertificateTimestampPublicGoodCertificate(t *testing.T) {
	tr := data.TrustedRoot(t, "public-good.json")
	entity := data.Bundle(t, "sigstore.js@2.0.0-provenance.sigstore.json")
	vc, err := entity.VerificationContent()
	require.NoError(t, err)
	leaf := vc.Certificate()
	require.NotNil(t, leaf)

	var chains [][]*x509.Certificate
	for _, ca := range tr.FulcioCertificateAuthorities() {
		chains, err = ca.Verify(leaf, leaf.NotBefore.Add(time.Minute))
		if err == nil {
			break
		}
	}
	require.NoError(t, err)
	require.NotEmpty(t, chains)
	chain := chains[0]
	require.GreaterOrEqual(t, len(chain), 3, "expected leaf, intermediate, and root")

	assert.NoError(t, verify.VerifySignedCertificateTimestamp(chains, 1, tr))

	// The certificate only carries an SCT from one log.
	assert.Error(t, verify.VerifySignedCertificateTimestamp(chains, 2, tr))

	// The SCT covers the hash of the direct issuer's key, so substituting the
	// root for the intermediate must fail.
	wrongIssuer := [][]*x509.Certificate{{leaf, chain[len(chain)-1]}}
	assert.Error(t, verify.VerifySignedCertificateTimestamp(wrongIssuer, 1, tr))

	// A chain without an issuer cannot be verified.
	assert.Error(t, verify.VerifySignedCertificateTimestamp([][]*x509.Certificate{{leaf}}, 1, tr))

	// Verification succeeds if any chain has the right issuer.
	assert.NoError(t, verify.VerifySignedCertificateTimestamp(append(wrongIssuer, chain), 1, tr))

	// The same log ID with a different key must fail.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKey := make(map[string]*root.TransparencyLog)
	expired := make(map[string]*root.TransparencyLog)
	for id, ctLog := range tr.CTLogs() {
		withOtherKey := *ctLog
		withOtherKey.PublicKey = &otherKey.PublicKey
		wrongKey[id] = &withOtherKey

		withEarlyEnd := *ctLog
		withEarlyEnd.ValidityPeriodEnd = leaf.NotBefore.Add(-24 * time.Hour)
		expired[id] = &withEarlyEnd
	}
	assert.Error(t, verify.VerifySignedCertificateTimestamp(chains, 1, &ctLogOverride{TrustedMaterial: tr, ctLogs: wrongKey}))

	// An SCT issued after the end of the log's validity period must fail.
	assert.Error(t, verify.VerifySignedCertificateTimestamp(chains, 1, &ctLogOverride{TrustedMaterial: tr, ctLogs: expired}))

	// With no trusted CT logs, nothing can be verified.
	assert.Error(t, verify.VerifySignedCertificateTimestamp(chains, 1, &ctLogOverride{TrustedMaterial: tr}))
}
