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

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestTimestampAuthorityVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthority(entity, virtualSigstore, 1)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthority(entity, virtualSigstore2, 1)
	assert.Error(t, err) // different sigstore instance should fail to verify
}

type dupTimestampEntity struct {
	*ca.TestEntity
}

func (e *dupTimestampEntity) Timestamps() ([][]byte, error) {
	timestamps, err := e.TestEntity.Timestamps()
	if err != nil {
		return nil, err
	}

	return append(timestamps, timestamps[0]), nil
}

func TestDuplicateTimestamps(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthority(&dupTimestampEntity{entity}, virtualSigstore, 1)
	assert.Error(t, err) // duplicate timestamps should fail to verify
}

type badTSASignatureEntity struct {
	*ca.TestEntity
}

func (e *badTSASignatureEntity) Timestamps() ([][]byte, error) {
	return [][]byte{[]byte("bad signature")}, nil
}

func TestBadTSASignature(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthority(&badTSASignatureEntity{entity}, virtualSigstore, 1)
	assert.Error(t, err)
}

type customTSAChainTrustedMaterial struct {
	*ca.VirtualSigstore
	tsaChain []root.CertificateAuthority
}

func (i *customTSAChainTrustedMaterial) TSACertificateAuthorities() []root.CertificateAuthority {
	return i.tsaChain
}

func TestBadTSACertificateChain(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	ca1 := virtualSigstore.TSACertificateAuthorities()[0]
	ca2 := virtualSigstore2.TSACertificateAuthorities()[0]
	badChain := root.CertificateAuthority{
		Root:                ca2.Root,
		Intermediates:       ca2.Intermediates,
		Leaf:                ca1.Leaf,
		ValidityPeriodStart: ca1.ValidityPeriodStart,
		ValidityPeriodEnd:   ca1.ValidityPeriodEnd,
	}

	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthority(entity, &customTSAChainTrustedMaterial{VirtualSigstore: virtualSigstore, tsaChain: []root.CertificateAuthority{badChain}}, 1)
	assert.Error(t, err)
}

func TestBadTSACertificateChainOutsideValidityPeriod(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	ca := virtualSigstore.TSACertificateAuthorities()[0]

	for _, test := range []struct {
		name string
		err  bool
		ca   root.CertificateAuthority
	}{
		{
			name: "valid",
			err:  false,
			ca: root.CertificateAuthority{
				Root:          ca.Root,
				Intermediates: ca.Intermediates,
				Leaf:          ca.Leaf,
				// ValidityPeriod is not set, so it should always be valid
			},
		},
		{
			name: "invalid: start time in the future",
			err:  true,
			ca: root.CertificateAuthority{
				Root:                ca.Root,
				Intermediates:       ca.Intermediates,
				Leaf:                ca.Leaf,
				ValidityPeriodStart: time.Now().Add(10 * time.Minute),
			},
		},
		{
			name: "invalid: end time in the past",
			err:  true,
			ca: root.CertificateAuthority{
				Root:              ca.Root,
				Intermediates:     ca.Intermediates,
				Leaf:              ca.Leaf,
				ValidityPeriodEnd: time.Now().Add(-10 * time.Minute),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", []byte("statement"))
			assert.NoError(t, err)

			_, err = verify.VerifyTimestampAuthority(entity, &customTSAChainTrustedMaterial{VirtualSigstore: virtualSigstore, tsaChain: []root.CertificateAuthority{test.ca}}, 1)
			if test.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
