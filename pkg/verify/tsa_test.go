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

	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(entity, virtualSigstore, 1)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(entity, virtualSigstore2, 1)
	assert.Error(t, err) // different sigstore instance should fail to verify

	untrustedEntity, err := virtualSigstore2.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(&oneTrustedOneUntrustedTimestampEntity{entity, untrustedEntity}, virtualSigstore, 1)
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(&oneTrustedOneUntrustedTimestampEntity{entity, untrustedEntity}, virtualSigstore, 2)
	assert.Error(t, err) // only 1 trusted should not meet threshold of 2
}

func TestTimestampAuthorityVerifierWithoutThreshold(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	var ts []verify.Timestamp

	// expect one verified timestamp
	ts, err = verify.VerifyTimestampAuthority(entity, virtualSigstore)
	assert.NoError(t, err)
	assert.Len(t, ts, 1)

	// no failure, but also no verified timestamps
	ts, err = verify.VerifyTimestampAuthority(entity, virtualSigstore2)
	assert.NoError(t, err)
	assert.Empty(t, ts)
}

type oneTrustedOneUntrustedTimestampEntity struct {
	*ca.TestEntity
	UntrustedTestEntity *ca.TestEntity
}

func (e *oneTrustedOneUntrustedTimestampEntity) Timestamps() ([][]byte, error) {
	timestamps, err := e.TestEntity.Timestamps()
	if err != nil {
		return nil, err
	}

	untrustedTimestamps, err := e.UntrustedTestEntity.Timestamps()
	if err != nil {
		return nil, err
	}

	return append(timestamps, untrustedTimestamps...), nil
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

	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(&dupTimestampEntity{entity}, virtualSigstore, 1)
	assert.ErrorContains(t, err, "duplicate timestamps found")
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

	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(&badTSASignatureEntity{entity}, virtualSigstore, 1)
	assert.Error(t, err)
}

type customTSAChainTrustedMaterial struct {
	*ca.VirtualSigstore
	tsaChain []root.CertificateAuthority
}

func (i *customTSAChainTrustedMaterial) TimestampingAuthorities() []root.CertificateAuthority {
	return i.tsaChain
}

func TestBadTSACertificateChain(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	ca1 := virtualSigstore.TimestampingAuthorities()[0]
	ca2 := virtualSigstore2.TimestampingAuthorities()[0]
	badChain := root.CertificateAuthority{
		Root:                ca2.Root,
		Intermediates:       ca2.Intermediates,
		Leaf:                ca1.Leaf,
		ValidityPeriodStart: ca1.ValidityPeriodStart,
		ValidityPeriodEnd:   ca1.ValidityPeriodEnd,
	}

	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(entity, &customTSAChainTrustedMaterial{VirtualSigstore: virtualSigstore, tsaChain: []root.CertificateAuthority{badChain}}, 1)
	assert.Error(t, err)
}

func TestBadTSACertificateChainOutsideValidityPeriod(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	ca := virtualSigstore.TimestampingAuthorities()[0]

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
			entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
			assert.NoError(t, err)

			_, err = verify.VerifyTimestampAuthorityWithThreshold(entity, &customTSAChainTrustedMaterial{VirtualSigstore: virtualSigstore, tsaChain: []root.CertificateAuthority{test.ca}}, 1)
			if test.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type tooManyTimestampsEntity struct {
	*ca.TestEntity
}

func (e *tooManyTimestampsEntity) Timestamps() ([][]byte, error) {
	timestamps, err := e.TestEntity.Timestamps()
	if err != nil {
		return nil, err
	}

	for i := 0; i < 32; i++ {
		timestamps = append(timestamps, timestamps[0])
	}

	return timestamps, nil
}

func TestTooManyTimestamps(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", []byte("statement"))
	assert.NoError(t, err)

	_, err = verify.VerifyTimestampAuthorityWithThreshold(&tooManyTimestampsEntity{entity}, virtualSigstore, 1)
	assert.ErrorContains(t, err, "too many signed timestamps")
}
