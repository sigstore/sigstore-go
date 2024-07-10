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

package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

type dsseSigner struct {
	pk *ecdsa.PrivateKey
}

func (d *dsseSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return d.pk.Sign(rand.Reader, digest[:], nil)
}

func (d *dsseSigner) KeyID() (string, error) {
	return "", nil
}

type envelopeContent struct {
	EnvelopeContent
	e *dsse.Envelope
}

func (e *envelopeContent) RawEnvelope() *dsse.Envelope {
	return e.e
}

func TestVerifyEnvelope(t *testing.T) {
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubk := privk.Public().(*ecdsa.PublicKey)
	assert.NoError(t, err)

	var s = dsseSigner{
		pk: privk,
	}

	testcases := []struct {
		count int
		fail  bool
	}{
		{
			count: 0,
			fail:  true,
		},
		{
			count: 1,
			fail:  false,
		},
		{
			count: 2,
			fail:  true,
		},
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("Test DSSE verify with %d signatures", tc.count),
			func(t *testing.T) {
				var e *dsse.Envelope

				if tc.count == 0 {
					// Need to create the envelope manually
					e = &dsse.Envelope{
						PayloadType: "test-payload-type",
						// b64(test-payload)
						Payload: "dGVzdC1wYXlsb2Fk",
					}
				} else {
					var signers []dsse.Signer

					for i := 0; i < tc.count; i++ {
						signers = append(signers, &s)
					}

					es, err := dsse.NewEnvelopeSigner(signers...)
					assert.NoError(t, err)
					e, err = es.SignPayload(context.Background(),
						"test-payload-type",
						[]byte("test-payload"))
					assert.NoError(t, err)
				}
				sigver, err := signature.LoadECDSAVerifier(pubk, crypto.SHA256)
				assert.NoError(t, err)
				err = verifyEnvelope(
					sigver,
					&envelopeContent{
						e: e,
					},
				)

				if tc.fail {
					assert.True(t, errors.Is(err, ErrInvSigCount))
				} else {
					assert.NoError(t, err)
				}
			})
	}

}
