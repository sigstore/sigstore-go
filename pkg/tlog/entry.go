package tlog

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

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
	RekorEntry           types.EntryImpl
	logEntryAnon         models.LogEntryAnon
	signedEntryTimestamp []byte
}

var ErrNilValue = errors.New("validation error: nil value in transaction log entry")

// ParseEntry decodes the entry bytes to a specific entry type (types.EntryImpl).
func ParseEntry(protoEntry *v1.TransparencyLogEntry) (entry *Entry, kind string, version string, err error) {
	if protoEntry == nil ||
		protoEntry.CanonicalizedBody == nil ||
		protoEntry.IntegratedTime == 0 ||
		protoEntry.LogIndex == 0 ||
		protoEntry.LogId == nil ||
		protoEntry.LogId.KeyId == nil ||
		protoEntry.KindVersion == nil {
		return nil, "", "", ErrNilValue
	}
	entry = &Entry{
		logEntryAnon: models.LogEntryAnon{
			Body:           base64.StdEncoding.EncodeToString(protoEntry.CanonicalizedBody),
			IntegratedTime: swag.Int64(protoEntry.IntegratedTime),
			LogIndex:       swag.Int64(protoEntry.LogIndex),
			LogID:          swag.String(string(protoEntry.LogId.KeyId)),
		},
	}
	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(protoEntry.CanonicalizedBody), runtime.JSONConsumer())
	if err != nil {
		return nil, "", "", err
	}

	entry.RekorEntry, err = types.UnmarshalEntry(pe)
	if err != nil {
		return nil, "", "", err
	}
	entry.signedEntryTimestamp = protoEntry.InclusionPromise.SignedEntryTimestamp

	kind = pe.Kind()
	version = entry.RekorEntry.APIVersion()
	if kind != protoEntry.KindVersion.Kind || version != protoEntry.KindVersion.Version {
		return nil, "", "", fmt.Errorf("kind and version mismatch: %s/%s != %s/%s", kind, version, protoEntry.KindVersion.Kind, protoEntry.KindVersion.Version)
	}

	return entry, kind, version, nil
}

func ValidateEntry(entry *Entry) error {
	switch e := entry.RekorEntry.(type) {
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

func VerifySET(entry *Entry) error {
	rekorPayload := cbundle.RekorPayload{
		Body:           entry.logEntryAnon.Body,
		IntegratedTime: *entry.logEntryAnon.IntegratedTime,
		LogIndex:       *entry.logEntryAnon.LogIndex,
		LogID:          hex.EncodeToString([]byte(*entry.logEntryAnon.LogID)),
	}

	// TODO: pass in rekor keys out of band
	publicKeys, err := cosign.GetRekorPubs(context.TODO())
	if err != nil {
		return fmt.Errorf("retrieving rekor public key: %w", err)
	}

	pubKey, ok := publicKeys.Keys[hex.EncodeToString([]byte(*entry.logEntryAnon.LogID))]
	if !ok {
		return errors.New("rekor log public key not found for payload")
	}

	ecdsaKey := pubKey.PubKey.(*ecdsa.PublicKey)
	return cosign.VerifySET(rekorPayload, entry.signedEntryTimestamp, ecdsaKey)
}
