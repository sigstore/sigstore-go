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
	"github.com/sigstore/rekor/pkg/generated/models"
	rekorVerify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const dsse string = "dsse"
const hashedrekord string = "hashedrekord"
const intoto string = "intoto"
const v001 string = "0.0.1"
const v002 string = "0.0.2"

type Entry struct {
	rekorEntry           models.ProposedEntry
	logEntryAnon         models.LogEntryAnon
	signedEntryTimestamp []byte
	version              string
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

	entry := &Entry{
		rekorEntry: pe,
		logEntryAnon: models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(body),
			IntegratedTime: swag.Int64(integratedTime),
			LogIndex:       swag.Int64(logIndex),
			LogID:          swag.String(string(logID)),
		},
	}

	switch entry.rekorEntry.Kind() {
	case dsse:
		entry.version = *(pe.(*models.DSSE).APIVersion)
	case hashedrekord:
		entry.version = *(pe.(*models.Hashedrekord).APIVersion)
	case intoto:
		entry.version = *(pe.(*models.Intoto).APIVersion)
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

// ParseEntry decodes the entry bytes to a specific entry type (types.EntryImpl).
func ParseEntry(protoEntry *v1.TransparencyLogEntry) (entry *Entry, err error) {
	if protoEntry == nil ||
		protoEntry.CanonicalizedBody == nil ||
		protoEntry.IntegratedTime == 0 ||
		protoEntry.LogIndex == 0 ||
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

	if entry.rekorEntry.Kind() != protoEntry.KindVersion.Kind || entry.version != protoEntry.KindVersion.Version {
		return nil, fmt.Errorf("kind and version mismatch: %s/%s != %s/%s", entry.rekorEntry.Kind(), entry.version, protoEntry.KindVersion.Kind, protoEntry.KindVersion.Version)
	}

	return entry, nil
}

func ValidateEntry(entry *Entry) error {
	switch entry.rekorEntry.Kind() {
	case dsse:
		err := entry.rekorEntry.(*models.DSSE).Validate(strfmt.Default)
		if err != nil {
			return err
		}
	case hashedrekord:
		err := entry.rekorEntry.(*models.Hashedrekord).Validate(strfmt.Default)
		if err != nil {
			return err
		}
	case intoto:
		err := entry.rekorEntry.(*models.Intoto).Validate(strfmt.Default)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported entry type: %s", entry.rekorEntry.Kind())
	}

	return nil
}

func (entry *Entry) IntegratedTime() time.Time {
	return time.Unix(*entry.logEntryAnon.IntegratedTime, 0)
}

func (entry *Entry) Signature() []byte {
	switch entry.rekorEntry.Kind() {
	case dsse:
		if entry.version == v001 {
			specJSON, err := json.Marshal(entry.rekorEntry.(*models.DSSE).Spec)
			if err != nil {
				return []byte{}
			}

			dsseObj := &models.DSSEV001Schema{}
			err = json.Unmarshal(specJSON, dsseObj)
			if err != nil {
				return []byte{}
			}

			signature := *dsseObj.Signatures[0].Signature
			sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
			if err != nil {
				return []byte{}
			}
			return sigBytes
		}
	case hashedrekord:
		if entry.version == v001 {
			specJSON, err := json.Marshal(entry.rekorEntry.(*models.Hashedrekord).Spec)
			if err != nil {
				return []byte{}
			}

			hashedrekordObj := &models.HashedrekordV001Schema{}
			err = json.Unmarshal(specJSON, hashedrekordObj)
			if err != nil {
				return []byte{}
			}

			return hashedrekordObj.Signature.Content
		}
	case intoto:
		if entry.version == v002 {
			specJSON, err := json.Marshal(entry.rekorEntry.(*models.Intoto).Spec)
			if err != nil {
				return []byte{}
			}

			intotoObj := &models.IntotoV002Schema{}
			err = json.Unmarshal(specJSON, intotoObj)
			if err != nil {
				return []byte{}
			}

			signature := *intotoObj.Content.Envelope.Signatures[0].Sig
			sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
			if err != nil {
				return []byte{}
			}
			return sigBytes
		}
	}

	return []byte{}
}

func (entry *Entry) PublicKey() any {
	var pemString []byte

	switch entry.rekorEntry.Kind() {
	case dsse:
		if entry.version == v001 {
			specJSON, err := json.Marshal(entry.rekorEntry.(*models.DSSE).Spec)
			if err != nil {
				return []byte{}
			}

			dsseObj := &models.DSSEV001Schema{}
			err = json.Unmarshal(specJSON, dsseObj)
			if err != nil {
				return nil
			}

			pemString = []byte(*dsseObj.Signatures[0].Verifier)
		}
	case hashedrekord:
		if entry.version == v001 {
			specJSON, err := json.Marshal(entry.rekorEntry.(*models.Hashedrekord).Spec)
			if err != nil {
				return []byte{}
			}

			hashedrekordObj := &models.HashedrekordV001Schema{}
			err = json.Unmarshal(specJSON, hashedrekordObj)
			if err != nil {
				return nil
			}

			pemString = []byte(hashedrekordObj.Signature.PublicKey.Content)
		}
	case intoto:
		if entry.version == v002 {
			specJSON, err := json.Marshal(entry.rekorEntry.(*models.Intoto).Spec)
			if err != nil {
				return []byte{}
			}

			intotoObj := &models.IntotoV002Schema{}
			err = json.Unmarshal(specJSON, intotoObj)
			if err != nil {
				return []byte{}
			}

			pemString = []byte(*intotoObj.Content.Envelope.Signatures[0].PublicKey)
		}
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

func (entry *Entry) HasInclusionPromise() bool {
	return entry.signedEntryTimestamp != nil
}

func (entry *Entry) HasInclusionProof() bool {
	return entry.logEntryAnon.Verification != nil
}

func VerifyInclusion(entry *Entry, verifier signature.Verifier) error {
	err := rekorVerify.VerifyInclusion(context.TODO(), &entry.logEntryAnon)
	if err != nil {
		return err
	}

	err = rekorVerify.VerifyCheckpointSignature(&entry.logEntryAnon, verifier)
	if err != nil {
		return err
	}

	return nil
}

func VerifySET(entry *Entry, verifiers map[string]*root.TlogAuthority) error {
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
