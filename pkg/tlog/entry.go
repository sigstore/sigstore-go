package tlog

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	intoto_v002 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.2"
)

type Entry struct {
	kind                 string
	version              string
	rekorEntry           types.EntryImpl
	logEntryAnon         models.LogEntryAnon
	signedEntryTimestamp []byte
}

var ErrNilValue = errors.New("validation error: nil value in transaction log entry")

func NewEntry(body []byte, integratedTime int64, logIndex int64, logID []byte, signedEntryTimestamp []byte) (*Entry, error) {
	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	rekorEntry, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}
	return &Entry{
		rekorEntry: rekorEntry,
		logEntryAnon: models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(body),
			IntegratedTime: swag.Int64(integratedTime),
			LogIndex:       swag.Int64(logIndex),
			LogID:          swag.String(string(logID)),
		},
		signedEntryTimestamp: signedEntryTimestamp,
		kind:                 pe.Kind(),
		version:              rekorEntry.APIVersion(),
	}, nil
}

// ParseEntry decodes the entry bytes to a specific entry type (types.EntryImpl).
func ParseEntry(protoEntry *v1.TransparencyLogEntry) (entry *Entry, err error) {
	if protoEntry == nil ||
		protoEntry.CanonicalizedBody == nil ||
		protoEntry.IntegratedTime == 0 ||
		protoEntry.LogIndex == 0 ||
		protoEntry.LogId == nil ||
		protoEntry.LogId.KeyId == nil ||
		protoEntry.KindVersion == nil ||
		protoEntry.InclusionPromise == nil ||
		protoEntry.InclusionPromise.SignedEntryTimestamp == nil {
		return nil, ErrNilValue
	}
	entry, err = NewEntry(protoEntry.CanonicalizedBody, protoEntry.IntegratedTime, protoEntry.LogIndex, protoEntry.LogId.KeyId, protoEntry.InclusionPromise.SignedEntryTimestamp)
	if err != nil {
		return nil, err
	}

	if entry.kind != protoEntry.KindVersion.Kind || entry.version != protoEntry.KindVersion.Version {
		return nil, fmt.Errorf("kind and version mismatch: %s/%s != %s/%s", entry.kind, entry.version, protoEntry.KindVersion.Kind, protoEntry.KindVersion.Version)
	}

	return entry, nil
}

func ValidateEntry(entry *Entry) error {
	switch e := entry.rekorEntry.(type) {
	case *intoto_v002.V002Entry:
		if e.IntotoObj.Content == nil {
			return fmt.Errorf("intoto entry has no content")
		}
		if e.IntotoObj.Content.Hash == nil {
			return fmt.Errorf("intoto entry has no hash")
		}
		if e.IntotoObj.Content.Hash.Algorithm == nil {
			return fmt.Errorf("intoto entry has no hash algorithm")
		}
		if e.IntotoObj.Content.Hash.Value == nil {
			return fmt.Errorf("intoto entry has no hash value")
		}
		if e.IntotoObj.Content.PayloadHash.Algorithm == nil {
			return fmt.Errorf("intoto entry has no payload hash algorithm")
		}
		if e.IntotoObj.Content.PayloadHash.Value == nil {
			return fmt.Errorf("intoto entry has no payload hash value")
		}
	default:
		return fmt.Errorf("unsupported entry type: %T", e)
	}

	return nil
}

func (entry *Entry) IntegratedTime() time.Time {
	return time.Unix(*entry.logEntryAnon.IntegratedTime, 0)
}

func VerifySET(entry *Entry, verifiers map[string]*root.TlogVerifier) error {
	rekorPayload := cbundle.RekorPayload{
		Body:           entry.logEntryAnon.Body,
		IntegratedTime: *entry.logEntryAnon.IntegratedTime,
		LogIndex:       *entry.logEntryAnon.LogIndex,
		LogID:          hex.EncodeToString([]byte(*entry.logEntryAnon.LogID)),
	}

	verifier, ok := verifiers[hex.EncodeToString([]byte(*entry.logEntryAnon.LogID))]
	if !ok {
		return errors.New("rekor log public key not found for payload")
	}

	if (!verifier.ValidityPeriodStart.IsZero() && verifier.ValidityPeriodStart.After(entry.IntegratedTime())) ||
		(!verifier.ValidityPeriodEnd.IsZero() && verifier.ValidityPeriodEnd.Before(entry.IntegratedTime())) {
		return errors.New("rekor log public key not valid at payload integrated time")
	}

	ecdsaKey := verifier.PublicKey.(*ecdsa.PublicKey)
	return cosign.VerifySET(rekorPayload, entry.signedEntryTimestamp, ecdsaKey)
}
