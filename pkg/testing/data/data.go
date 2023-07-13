package data

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/github/sigstore-verifier/pkg/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Unmarshal returns the Go value for the given bytes
func Unmarshal[T any](t *testing.T, data []byte) T {
	var v T
	err := json.Unmarshal(data, &v)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

//go:embed sigstoreBundle.json
var SigstoreBundleRaw []byte

func TestBundle(t *testing.T, raw []byte) *bundle.ProtobufBundle {
	var b protobundle.Bundle
	err := protojson.Unmarshal(raw, &b)
	if err != nil {
		t.Fatal(err)
	}
	bun, err := bundle.NewProtobufBundle(&b)
	if err != nil {
		t.Fatal(err)
	}
	return bun
}

// SigstoreBundle returns a test *sigstore.Bundle
func SigstoreBundle(t *testing.T) *bundle.ProtobufBundle {
	return TestBundle(t, SigstoreBundleRaw)
}
