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

package tlog

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekortilespb "github.com/sigstore/rekor-tiles/pkg/generated/protobuf"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
	rekorVerify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/root"
)

type LogEntry interface {
	Kind() string
	Version() string
	HasInclusionPromise() bool
	HasInclusionProof() bool
	PublicKey() any
	Signature() []byte
	LogKeyID() string
	LogIndex() int64
	TransparencyLogEntry() *v1.TransparencyLogEntry
}

type Entry struct {
	kind                 string
	version              string
	rekorEntry           types.EntryImpl
	logEntryAnon         models.LogEntryAnon
	signedEntryTimestamp []byte
	tle                  *v1.TransparencyLogEntry
}

type rekorV1Entry = Entry

type rekorV2Entry struct {
	kind       string
	version    string
	rekorEntry *rekortilespb.Entry
	tle        *v1.TransparencyLogEntry
}

type RekorPayload struct {
	Body           interface{} `json:"body"`
	IntegratedTime int64       `json:"integratedTime"`
	LogIndex       int64       `json:"logIndex"`
	LogID          string      `json:"logID"` //nolint:tagliatelle
}

var ErrNilValue = errors.New("validation error: nil value in transaction log entry")

func NewEntry(body []byte, integratedTime int64, logIndex int64, logID []byte, signedEntryTimestamp []byte, inclusionProof *models.InclusionProof) (*Entry, error) {
	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	rekorEntry, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	entry := &Entry{
		rekorEntry: rekorEntry,
		logEntryAnon: models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(body),
			IntegratedTime: swag.Int64(integratedTime),
			LogIndex:       swag.Int64(logIndex),
			LogID:          swag.String(string(logID)),
		},
		kind:    pe.Kind(),
		version: rekorEntry.APIVersion(),
	}

	if len(signedEntryTimestamp) > 0 {
		entry.signedEntryTimestamp = signedEntryTimestamp
	}

	if inclusionProof != nil {
		entry.logEntryAnon.Verification = &models.LogEntryAnonVerification{
			InclusionProof: inclusionProof,
		}
	}

	return entry, nil
}

func ParseLogEntry(tle *v1.TransparencyLogEntry) (LogEntry, error) {
	if tle == nil {
		return nil, ErrNilValue
	}
	if tle.IntegratedTime != 0 {
		// rekor v1 entry
		return ParseEntry(tle)
	}
	if tle.CanonicalizedBody == nil ||
		tle.LogIndex < 0 ||
		tle.LogId == nil ||
		tle.LogId.KeyId == nil ||
		tle.KindVersion == nil ||
		tle.InclusionProof == nil {
		return nil, ErrNilValue
	}
	if tle.InclusionPromise != nil {
		return nil, fmt.Errorf("unexpected inclusion promise for Rekor v2 entry")
	}
	logEntryBody := rekortilespb.Entry{}
	err := protojson.Unmarshal(tle.CanonicalizedBody, &logEntryBody)
	if err != nil {
		return nil, fmt.Errorf("parsing TLE canonicalized body: %w", err)
	}
	entry := &rekorV2Entry{
		kind:       tle.KindVersion.Kind,
		version:    tle.KindVersion.Version,
		rekorEntry: &logEntryBody,
		tle:        tle,
	}
	return entry, nil
}

// ParseEntry decodes the entry bytes to a specific entry type (types.EntryImpl).
func ParseEntry(protoEntry *v1.TransparencyLogEntry) (entry *Entry, err error) {
	if protoEntry == nil ||
		protoEntry.CanonicalizedBody == nil ||
		protoEntry.IntegratedTime == 0 ||
		protoEntry.LogIndex < 0 ||
		protoEntry.LogId == nil ||
		protoEntry.LogId.KeyId == nil ||
		protoEntry.KindVersion == nil {
		return nil, ErrNilValue
	}

	signedEntryTimestamp := []byte{}
	if protoEntry.InclusionPromise != nil && protoEntry.InclusionPromise.SignedEntryTimestamp != nil {
		signedEntryTimestamp = protoEntry.InclusionPromise.SignedEntryTimestamp
	}

	var inclusionProof *models.InclusionProof

	if protoEntry.InclusionProof != nil {
		var hashes []string

		for _, v := range protoEntry.InclusionProof.Hashes {
			hashes = append(hashes, hex.EncodeToString(v))
		}

		rootHash := hex.EncodeToString(protoEntry.InclusionProof.RootHash)

		if protoEntry.InclusionProof.Checkpoint == nil {
			return nil, fmt.Errorf("inclusion proof missing required checkpoint")
		}
		if protoEntry.InclusionProof.Checkpoint.Envelope == "" {
			return nil, fmt.Errorf("inclusion proof checkpoint empty")
		}

		inclusionProof = &models.InclusionProof{
			LogIndex:   swag.Int64(protoEntry.InclusionProof.LogIndex),
			RootHash:   &rootHash,
			TreeSize:   swag.Int64(protoEntry.InclusionProof.TreeSize),
			Hashes:     hashes,
			Checkpoint: swag.String(protoEntry.InclusionProof.Checkpoint.Envelope),
		}
	}

	entry, err = NewEntry(protoEntry.CanonicalizedBody, protoEntry.IntegratedTime, protoEntry.LogIndex, protoEntry.LogId.KeyId, signedEntryTimestamp, inclusionProof)
	if err != nil {
		return nil, err
	}

	if entry.kind != protoEntry.KindVersion.Kind || entry.version != protoEntry.KindVersion.Version {
		return nil, fmt.Errorf("kind and version mismatch: %s/%s != %s/%s", entry.kind, entry.version, protoEntry.KindVersion.Kind, protoEntry.KindVersion.Version)
	}
	entry.tle = protoEntry

	return entry, nil
}

func ValidateLogEntryBody(entry LogEntry) error {
	if e, ok := entry.(*rekorV1Entry); ok {
		return ValidateEntry(e)
	}
	return nil // TODO: validate rekorv2 entry?
}

// DEPRECATED: use ValidateLogEntryBody
func ValidateEntry(entry *Entry) error {
	switch e := entry.rekorEntry.(type) {
	case *dsse_v001.V001Entry:
		err := e.DSSEObj.Validate(strfmt.Default)
		if err != nil {
			return err
		}
	case *hashedrekord_v001.V001Entry:
		err := e.HashedRekordObj.Validate(strfmt.Default)
		if err != nil {
			return err
		}
	case *intoto_v002.V002Entry:
		err := e.IntotoObj.Validate(strfmt.Default)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported entry type: %T", e)
	}

	return nil
}

func (entry *Entry) IntegratedTime() time.Time {
	return time.Unix(*entry.logEntryAnon.IntegratedTime, 0)
}

func (entry *Entry) Kind() string {
	return entry.kind
}

func (entry *Entry) Version() string {
	return entry.version
}

func (entry *Entry) Signature() []byte {
	switch e := entry.rekorEntry.(type) {
	case *dsse_v001.V001Entry:
		sigBytes, err := base64.StdEncoding.DecodeString(*e.DSSEObj.Signatures[0].Signature)
		if err != nil {
			return []byte{}
		}
		return sigBytes
	case *hashedrekord_v001.V001Entry:
		return e.HashedRekordObj.Signature.Content
	case *intoto_v002.V002Entry:
		sigBytes, err := base64.StdEncoding.DecodeString(string(*e.IntotoObj.Content.Envelope.Signatures[0].Sig))
		if err != nil {
			return []byte{}
		}
		return sigBytes
	}

	return []byte{}
}

func (entry *Entry) PublicKey() any {
	var pemString []byte

	switch e := entry.rekorEntry.(type) {
	case *dsse_v001.V001Entry:
		pemString = []byte(*e.DSSEObj.Signatures[0].Verifier)
	case *hashedrekord_v001.V001Entry:
		pemString = []byte(e.HashedRekordObj.Signature.PublicKey.Content)
	case *intoto_v002.V002Entry:
		pemString = []byte(*e.IntotoObj.Content.Envelope.Signatures[0].PublicKey)
	}

	certBlock, _ := pem.Decode(pemString)

	var pk any
	var err error

	pk, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		pk, err = x509.ParsePKIXPublicKey(certBlock.Bytes)
		if err != nil {
			return nil
		}
	}

	return pk
}

func (entry *Entry) LogKeyID() string {
	return *entry.logEntryAnon.LogID
}

func (entry *Entry) LogIndex() int64 {
	return *entry.logEntryAnon.LogIndex
}

func (entry *Entry) Body() any {
	return entry.logEntryAnon.Body
}

func (entry *Entry) HasInclusionPromise() bool {
	return entry.signedEntryTimestamp != nil
}

func (entry *Entry) HasInclusionProof() bool {
	return entry.logEntryAnon.Verification != nil
}

func (entry *Entry) TransparencyLogEntry() *v1.TransparencyLogEntry {
	return entry.tle
}

func (entry *rekorV2Entry) Kind() string {
	return entry.kind
}

func (entry *rekorV2Entry) Version() string {
	return entry.version
}

func (entry *rekorV2Entry) PublicKey() any {
	verifier := entry.rekorEntry.GetSpec().GetHashedRekordV0_0_2().GetSignature().GetVerifier() // TODO: dsse
	pubKey := verifier.GetPublicKey()
	if pubKey != nil {
		return pubKey
	}
	return verifier.GetX509Certificate()
}

func (entry *rekorV2Entry) LogKeyID() string {
	return string(entry.tle.GetLogId().GetKeyId())
}

func (entry *rekorV2Entry) LogIndex() int64 {
	return entry.tle.GetLogIndex()
}

func (entry *rekorV2Entry) HasInclusionPromise() bool {
	return false
}

func (entry *rekorV2Entry) HasInclusionProof() bool {
	return true
}

func (entry *rekorV2Entry) Signature() []byte {
	return entry.rekorEntry.GetSpec().GetHashedRekordV0_0_2().GetSignature().GetContent() // TODO: dsse
}

func (entry *rekorV2Entry) TransparencyLogEntry() *v1.TransparencyLogEntry {
	return entry.tle
}

func VerifyInclusion(entry *Entry, verifier signature.Verifier) error {
	err := rekorVerify.VerifyInclusion(context.Background(), &entry.logEntryAnon)
	if err != nil {
		return err
	}

	err = rekorVerify.VerifyCheckpointSignature(&entry.logEntryAnon, verifier)
	if err != nil {
		return err
	}

	return nil
}

func VerifySET(entry *Entry, verifiers map[string]*root.TransparencyLog) error {
	rekorPayload := RekorPayload{
		Body:           entry.logEntryAnon.Body,
		IntegratedTime: *entry.logEntryAnon.IntegratedTime,
		LogIndex:       *entry.logEntryAnon.LogIndex,
		LogID:          hex.EncodeToString([]byte(*entry.logEntryAnon.LogID)),
	}

	verifier, ok := verifiers[hex.EncodeToString([]byte(*entry.logEntryAnon.LogID))]
	if !ok {
		return errors.New("rekor log public key not found for payload")
	}
	if verifier.ValidityPeriodStart.IsZero() {
		return errors.New("rekor validity period start time not set")
	}
	if (verifier.ValidityPeriodStart.After(entry.IntegratedTime())) ||
		(!verifier.ValidityPeriodEnd.IsZero() && verifier.ValidityPeriodEnd.Before(entry.IntegratedTime())) {
		return errors.New("rekor log public key not valid at payload integrated time")
	}

	contents, err := json.Marshal(rekorPayload)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}
	canonicalized, err := jsoncanonicalizer.Transform(contents)
	if err != nil {
		return fmt.Errorf("canonicalizing: %w", err)
	}

	hash := sha256.Sum256(canonicalized)
	if ecdsaPublicKey, ok := verifier.PublicKey.(*ecdsa.PublicKey); !ok {
		return fmt.Errorf("unsupported public key type: %T", verifier.PublicKey)
	} else if !ecdsa.VerifyASN1(ecdsaPublicKey, hash[:], entry.signedEntryTimestamp) {
		return errors.New("unable to verify SET")
	}
	return nil
}
