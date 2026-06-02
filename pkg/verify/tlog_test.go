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
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
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

	var ts []root.Timestamp
	ts, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
	assert.NoError(t, err)
	// 1 verified timestamp
	assert.Len(t, ts, 1)

	ts, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, false)
	assert.NoError(t, err)
	// 0 verified timestamps, since integrated timestamps are ignored
	assert.Len(t, ts, 0)

	virtualSigstore2, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	_, err = verify.VerifyTlogEntry(entity, virtualSigstore2, 1, true)
	assert.Error(t, err) // different sigstore instance should fail to verify

	// Attempt to use tlog with integrated time outside certificate validity.
	//
	// This time was chosen assuming the Fulcio signing certificate expires
	// after 5 minutes, but while the TSA intermediate is still valid (2 hours).
	entity, err = virtualSigstore.AttestAtTime("foo@example.com", "issuer", statement, time.Now().Add(30*time.Minute), false)
	assert.NoError(t, err)

	_, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
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
	_, err = verify.VerifyTlogEntry(&oneTrustedOneUntrustedLogEntry{entity, untrustedEntity}, virtualSigstore, 1, true)
	assert.NoError(t, err)

	// failure: threshold of 2 is not met since 1 untrusted entry is ignored
	_, err = verify.VerifyTlogEntry(&oneTrustedOneUntrustedLogEntry{entity, untrustedEntity}, virtualSigstore, 2, true)
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
		invalidEntry, err := tlog.NewEntry(body, entry.IntegratedTime().Unix(), entry.LogIndex(), []byte(entry.LogKeyID()), nil, nil) //nolint:staticcheck
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
	_, err = verify.VerifyTlogEntry(&invalidTLogEntity{entity}, virtualSigstore, 1, true)
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
	_, err = verify.VerifyTlogEntry(&noTLogEntity{entity}, virtualSigstore, 1, true)
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

	_, err = verify.VerifyTlogEntry(&dupTlogEntity{entity}, virtualSigstore, 1, true)
	assert.ErrorContains(t, err, "duplicate tlog entries found") // duplicate tlog entries should fail to verify
}

type sameLogIDDifferentIndexEntity struct {
	*ca.TestEntity
	VirtualSigstore *ca.VirtualSigstore
}

func (e *sameLogIDDifferentIndexEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}
	entry1 := entries[0]
	body, err := base64.StdEncoding.DecodeString(entry1.Body().(string))
	if err != nil {
		return nil, err
	}

	rekorLogID, err := e.VirtualSigstore.RekorLogID()
	if err != nil {
		return nil, err
	}
	rekorLogIDRaw, err := hex.DecodeString(rekorLogID)
	if err != nil {
		return nil, err
	}

	b2 := tlog.RekorPayload{
		LogID:          rekorLogID,
		IntegratedTime: entry1.IntegratedTime().Unix(),
		LogIndex:       entry1.LogIndex() + 1,
		Body:           entry1.Body().(string),
	}
	set2, err := e.VirtualSigstore.RekorSignPayload(b2)
	if err != nil {
		return nil, err
	}

	entry2, err := tlog.NewEntry(body, entry1.IntegratedTime().Unix(), entry1.LogIndex()+1, rekorLogIDRaw, set2, nil) //nolint:staticcheck
	if err != nil {
		return nil, err
	}
	return []*tlog.Entry{entry1, entry2}, nil
}

func TestSameLogIDDifferentIndexTlogEntries(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	wrappedEntity := &sameLogIDDifferentIndexEntity{
		TestEntity:      entity,
		VirtualSigstore: virtualSigstore,
	}

	// Threshold of 1 should succeed with 2 entries from the same log
	ts, err := verify.VerifyTlogEntry(wrappedEntity, virtualSigstore, 1, true)
	assert.NoError(t, err)
	// It must return exactly 1 observer timestamp (deduplicated)
	assert.Len(t, ts, 1)

	// Threshold of 2 should fail because both entries are from the same log (only 1 witness)
	_, err = verify.VerifyTlogEntry(wrappedEntity, virtualSigstore, 2, true)
	assert.ErrorContains(t, err, "not enough verified log entries from transparency log")
}

type tooManyTlogEntriesEntity struct {
	*ca.TestEntity
}

func (e *tooManyTlogEntriesEntity) TlogEntries() ([]*tlog.Entry, error) {
	entries, err := e.TestEntity.TlogEntries()
	if err != nil {
		return nil, err
	}
	for range 32 {
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

	_, err = verify.VerifyTlogEntry(&tooManyTlogEntriesEntity{entity}, virtualSigstore, 1, true)
	assert.ErrorContains(t, err, "too many tlog entries") // too many tlog entries should fail to verify
}

func TestOfflineInclusionProofVerification(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	integratedTime := time.Now().Add(5 * time.Minute)
	entity, err := virtualSigstore.AttestAtTime("foo@example.com", "issuer", statement, integratedTime, true)
	assert.NoError(t, err)

	_, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
	assert.NoError(t, err)
}

func TestInclusionProofAuditPath(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstoreWithExistingRekorEntry()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)
	integratedTime := time.Now().Add(5 * time.Minute)
	entity, err := virtualSigstore.AttestAtTime("foo@example.com", "issuer", statement, integratedTime, true)
	assert.NoError(t, err)

	_, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
	assert.NoError(t, err)
}

func TestTlogEntryDigestMismatch(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	artifact := []byte("hello world")
	entity, err := virtualSigstore.Sign("foo@example.com", "issuer", artifact)
	assert.NoError(t, err)

	// Verify should succeed normally
	_, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
	assert.NoError(t, err)

	// Now create an entity with mismatching digest
	fakeDigest := strings.Repeat("a", 32) // 32 bytes for sha256
	mismatchEntity := &mismatchDigestEntity{TestEntity: entity, fakeDigest: []byte(fakeDigest)}
	_, err = verify.VerifyTlogEntry(mismatchEntity, virtualSigstore, 1, true)
	assert.ErrorContains(t, err, "does not match artifact")
}

type mismatchDigestEntity struct {
	*ca.TestEntity
	fakeDigest []byte
}

func (e *mismatchDigestEntity) SignatureContent() (verify.SignatureContent, error) {
	sigContent, err := e.TestEntity.SignatureContent()
	if err != nil {
		return nil, err
	}
	return &mismatchSignatureContent{sigContent, e.fakeDigest}, nil
}

type mismatchSignatureContent struct {
	verify.SignatureContent
	fakeDigest []byte
}

func (c *mismatchSignatureContent) MessageSignatureContent() verify.MessageSignatureContent {
	msgSig := c.SignatureContent.MessageSignatureContent()
	if msgSig == nil {
		return nil
	}
	return &mismatchMessageSignatureContent{msgSig, c.fakeDigest}
}

type mismatchMessageSignatureContent struct {
	verify.MessageSignatureContent
	fakeDigest []byte
}

func (c *mismatchMessageSignatureContent) Digest() []byte {
	return c.fakeDigest
}

func TestTlogEntryDssePayloadHashMismatch(t *testing.T) {
	virtualSigstore, err := ca.NewVirtualSigstore()
	assert.NoError(t, err)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[],"predicate":{}}`)
	entity, err := virtualSigstore.Attest("foo@example.com", "issuer", statement)
	assert.NoError(t, err)

	// Verify should succeed normally
	_, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
	assert.NoError(t, err)

	// Now create an entity with mismatching envelope payload
	mismatchEntity := &mismatchEnvelopeEntity{TestEntity: entity}
	_, err = verify.VerifyTlogEntry(mismatchEntity, virtualSigstore, 1, true)
	assert.ErrorContains(t, err, "does not match envelope payload hash")
}

type mismatchEnvelopeEntity struct {
	*ca.TestEntity
}

func (e *mismatchEnvelopeEntity) SignatureContent() (verify.SignatureContent, error) {
	sigContent, err := e.TestEntity.SignatureContent()
	if err != nil {
		return nil, err
	}
	return &mismatchEnvelopeSignatureContent{sigContent}, nil
}

type mismatchEnvelopeSignatureContent struct {
	verify.SignatureContent
}

func (c *mismatchEnvelopeSignatureContent) EnvelopeContent() verify.EnvelopeContent {
	envContent := c.SignatureContent.EnvelopeContent()
	if envContent == nil {
		return nil
	}
	return &mismatchEnvelopeContentWrapper{envContent}
}

type mismatchEnvelopeContentWrapper struct {
	verify.EnvelopeContent
}

func (c *mismatchEnvelopeContentWrapper) RawEnvelope() *dsse.Envelope {
	env := c.EnvelopeContent.RawEnvelope()
	if env == nil {
		return nil
	}
	clone := &dsse.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("fake payload")),
		PayloadType: env.PayloadType,
		Signatures:  env.Signatures,
	}
	return clone
}

// TestTlogVerifierDSSEHashedRekordV2 verifies a DSSE envelope encoded as a Rekor v2 hashedrekord.
func TestTlogVerifierDSSEHashedRekordV2(t *testing.T) {
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"customFoo","subject":[{"name":"subject","digest":{"sha256":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}}],"predicate":{}}`)

	for _, tc := range []struct {
		name string
		alg  v1.PublicKeyDetails
	}{
		{"sha256", v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256},
		{"sha384", v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384},
		{"sha512", v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512},
		{"ed25519ph", v1.PublicKeyDetails_PKIX_ED25519_PH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			virtualSigstore, err := ca.NewVirtualSigstoreWithSigningAlg(tc.alg)
			assert.NoError(t, err)

			entity, err := virtualSigstore.AttestHashedRekordV2("foo@example.com", "issuer", statement)
			assert.NoError(t, err)

			_, err = verify.VerifyTlogEntry(entity, virtualSigstore, 1, true)
			assert.NoError(t, err)

			// Tampering with the envelope changes the reconstructed leaf hash, failing inclusion proof.
			mismatch := &mismatchEnvelopeEntity{TestEntity: entity}
			_, err = verify.VerifyTlogEntry(mismatch, virtualSigstore, 1, true)
			assert.ErrorContains(t, err, "verifying inclusion")
		})
	}
}
