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
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	rekorGeneratedClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
)

// TODO(issue#53): Add unit tests for online log verification and inclusion proofs
func TestTlogVerifier(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	var ts []verify.Timestamp
	ts, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, true, false)
	assert.NoError(t, err)
	// 1 verified timestamp
	assert.Len(t, ts, 1)

	ts, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, false, false)
	assert.NoError(t, err)
	// 0 verified timestamps, since integrated timestamps are ignored
	assert.Len(t, ts, 0)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore2, 1, true, false)
	assert.Error(t, err) // different sigstore instance should fail to verify

	// Attempt to use tlog with integrated time outside certificate validity.
	//
	// This time was chosen assuming the Fulcio signing certificate expires
	// after 5 minutes, but while the TSA intermediate is still valid (2 hours).
	entity, err = virtualSigstore.AttestAtTime("foo@example.com", "issuer", statement, time.Now().Add(30*time.Minute), false)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, true, false)
	assert.Error(t, err)
}

type oneTrustedOneUntrustedLogEntry struct {
	*ca.TestEntity
	UntrustedTestEntity *ca.TestEntity
}

func (e *oneTrustedOneUntrustedLogEntry) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}

	otherEntries, err := e.UntrustedTestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}

	return append(entries, otherEntries...), nil
}

func TestIgnoredTLogEntries(t *testing.T) {
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)

	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	untrustedSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	untrustedEntity, err := untrustedSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	// success: entry that cannot be verified is ignored
	_, err = verify.VerifyArtifactTransparencyLog(&oneTrustedOneUntrustedLogEntry{entity, untrustedEntity}, virtualSigstore, 1, true, false)
	assert.NoError(t, err)

	// failure: threshold of 2 is not met since 1 untrusted entry is ignored
	_, err = verify.VerifyArtifactTransparencyLog(&oneTrustedOneUntrustedLogEntry{entity, untrustedEntity}, virtualSigstore, 2, true, false)
	assert.Error(t, err)
}

// invalidTLogEntity constructs a bundle with a Rekor response, but without an inclusion proof or promise
type invalidTLogEntity struct {
	*ca.TestEntity
}

func (e *invalidTLogEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}
	var invalidEntries []*tlog.Entry
	for _, entry := range entries {
		body, err := base64.StdEncoding.DecodeString(entry.Body().(string))
		if err != nil {
			return nil, err
		}
		invalidEntry, err := tlog.NewEntry(body, entry.IntegratedTime().Unix(), entry.LogIndex(), []byte(entry.LogKeyID()), nil, nil)
		if err != nil {
			return nil, err
		}
		invalidEntries = append(invalidEntries, invalidEntry)
	}
	return invalidEntries, nil
}

func TestInvalidTLogEntries(t *testing.T) {
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)

	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	// failure: threshold of 1 is not met with invalid entry
	_, err = verify.VerifyArtifactTransparencyLog(&invalidTLogEntity{entity}, virtualSigstore, 1, true, false)
	assert.Error(t, err)
	if err.Error() != "entry must contain an inclusion proof and/or promise" {
		t.Errorf("expected error with missing proof/promises, got: %v", err.Error())
	}
}

type noTLogEntity struct {
	*ca.TestEntity
}

func (e *noTLogEntity) TlogEntries() ([]*tlog.Entry, error) {
	return []*tlog.Entry{}, nil
}

func TestNoTLogEntries(t *testing.T) {
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)

	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	// failure: threshold of 1 is not met with no entries
	_, err = verify.VerifyArtifactTransparencyLog(&noTLogEntity{entity}, virtualSigstore, 1, true, false)
	assert.Error(t, err)
	if !strings.Contains(err.Error(), "not enough verified log entries from transparency log") {
		t.Errorf("expected error with timestamp threshold, got: %v", err.Error())
	}
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
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(&dupTlogEntity{entity}, virtualSigstore, 1, true, false)
	assert.ErrorContains(t, err, "duplicate tlog entries found") // duplicate tlog entries should fail to verify
}

type tooManyTlogEntriesEntity struct {
	*ca.TestEntity
}

func (e *tooManyTlogEntriesEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}
	for i := 0; i < 32; i++ {
		entries = append(entries, entries[0])
	}

	return entries, nil
}

func TestMaxAllowedTlogEntries(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	_, err = verify.VerifyArtifactTransparencyLog(&tooManyTlogEntriesEntity{entity}, virtualSigstore, 1, true, false)
	assert.ErrorContains(t, err, "too many tlog entries") // too many tlog entries should fail to verify
}

type mockEntriesClient struct {
	Entries []*models.LogEntry
}

func (m *mockEntriesClient) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return nil, errors.New("not implemented")
}

func (m *mockEntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams, _ ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	resp := &entries.GetLogEntryByIndexOK{}
	if len(m.Entries) != 0 {
		for _, e := range m.Entries {
			for _, i := range *e {
				if *i.LogIndex == params.LogIndex {
					resp.Payload = *e
				}
			}
		}

		if resp.Payload == nil {
			resp.Payload = *m.Entries[0]
		}
	}
	return resp, nil
}

func (m *mockEntriesClient) GetLogEntryByUUID(_ *entries.GetLogEntryByUUIDParams, _ ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return nil, errors.New("not implemented")
}

func (m *mockEntriesClient) SearchLogQuery(_ *entries.SearchLogQueryParams, _ ...entries.ClientOption) (*entries.SearchLogQueryOK, error) {
	return nil, errors.New("not implemented")
}

func (m *mockEntriesClient) SetTransport(_ runtime.ClientTransport) {}

func TestOnlineVerification(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	integratedTime := time.Now().Add(5 * time.Minute)
	entity, err := virtualSigstore.AttestAtTime("foo@example.com", "issuer", statement, integratedTime, true)
	assert.NoError(t, err)
	base64Statement := base64.StdEncoding.EncodeToString(statement)
	verification := &models.LogEntryAnonVerification{}
	verification.InclusionProof, err = virtualSigstore.GetInclusionProof(statement)
	assert.NoError(t, err)
	logID, err := virtualSigstore.RekorLogID()
	assert.NoError(t, err)
	bundle := &tlog.RekorPayload{
		LogID:          logID,
		IntegratedTime: integratedTime.Unix(),
		LogIndex:       0,
		Body:           base64Statement,
	}
	verification.SignedEntryTimestamp, err = virtualSigstore.RekorSignPayload(*bundle)
	assert.NoError(t, err)

	var logEntry models.LogEntry = make(models.LogEntry)
	logEntry["foo"] = models.LogEntryAnon{
		Body:           base64Statement,
		IntegratedTime: swag.Int64(integratedTime.Unix()),
		LogIndex:       swag.Int64(0),
		LogID:          swag.String(logID),
		Verification:   verification,
	}
	mockRekor := &rekorGeneratedClient.Rekor{
		Entries: &mockEntriesClient{
			Entries: []*models.LogEntry{&logEntry},
		},
	}
	oldRekorClientGetter := verify.RekorClientGetter
	verify.RekorClientGetter = func(_ string) (*rekorGeneratedClient.Rekor, error) { return mockRekor, nil }
	defer func() { verify.RekorClientGetter = oldRekorClientGetter }()
	_, err = verify.VerifyArtifactTransparencyLog(entity, virtualSigstore, 1, true, true)
	assert.NoError(t, err)
}
