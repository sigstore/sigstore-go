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
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

func TestTlogVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", statement)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, false)
	assert.NoError(t, err)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore2, 1, false)
	assert.Error(t, err) // different sigstore instance should fail to verify

	// Attempt to use tlog with integrated time outside certificate validity.
	//
	// This time was chosen assuming the Fulcio signing certificate expires
	// after 5 minutes, but while the TSA intermediate is still valid (2 hours).
	entity, err = virtualSigstore.AttestAtTime("foo@fighters.com", "issuer", statement, time.Now().Add(30*time.Minute))
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, false)
	assert.Error(t, err)
}

type goodAndUntrustedLogEntry struct {
	*ca.TestEntity
	OtherTestEntity *ca.TestEntity
}

func (e *goodAndUntrustedLogEntry) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}

	otherEntries, err := e.OtherTestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}

	return append(entries, otherEntries...), nil
}

func TestIgnoredTLogEntries(t *testing.T) {
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)

	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	entity, err := virtualSigstore.Attest("foo@fighters.com", "issuer", statement)
	assert.NoError(t, err)

	otherSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	otherEntity, err := otherSigstore.Attest("foo@fighters.com", "issuer", statement)
	assert.NoError(t, err)

	// success: entry that cannot be verified is ignored
	_, err = verify.VerifyArtifactTransparencyLog(&goodAndUntrustedLogEntry{entity, otherEntity}, virtualSigstore, 1, false)
	assert.NoError(t, err)

	// failure: threshold of 2 is not met since 1 untrusted entry is ignored
	_, err = verify.VerifyArtifactTransparencyLog(&goodAndUntrustedLogEntry{entity, otherEntity}, virtualSigstore, 2, false)
	assert.Error(t, err)
}

type dupTlogEntity struct {
	*ca.TestEntity
}

func (e *dupTlogEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}

	return append(entries, entries[0]), nil
}

func TestDuplicateTlogEntries(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foofighters@example.com", "issuer", statement)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(&dupTlogEntity{entity}, virtualSigstore, 1, false)
	assert.Error(t, err) // duplicate tlog entries should fail to verify
}
