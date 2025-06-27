// Copyright 2025 The Sigstore Authors.
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
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/stretchr/testify/assert"
)

var entryBodyV2 = []byte(`{
  "apiVersion": "0.0.2",
  "kind": "hashedrekord",
  "spec": {
    "hashedRekordV002": {
      "data": {
        "algorithm": "SHA2_256",
        "digest": "dyj4ednYHjN4/zsjjBeeLahS9slp97Z67LTAVxjrjXw="
      },
      "signature": {
        "content": "MEQCIB+YPa9o3SN0sQ4uduGf+mZxwFfOhFZ0Cgy+p7Vt1o2SAiAPFDHqOAJLYmvtCWOsDyNY1H4V3zm4NEDYs3NyvHh1Pg==",
        "verifier": {
          "keyDetails": "PKIX_ECDSA_P256_SHA_256",
          "publicKey": {
            "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2slOf8eZcj2moW2t4UFj7vCL6QpDzkDqqSUmm4OJCVvIauKLxm0aGs3VMPPfauMPaMutn0/s3jg0rroFxoicyg=="
          }
        }
      }
    }
  }
}`)

var entryBodyV1 = []byte(`{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": {
			"signature": {
				"content": "MEQCIFrwIdVX8n5RM+Fy9fgCmaBc20jmksfL0XL08y1zx3XpAiB95HkXz37kTUzdykwuNStwCc5B9NKHtioD+3GYMuWU/w==",
				"publicKey": {
					"content": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFNHlQQ080MStjeGxEdENBUndTNDNvQU1YVWs3NApyWGZ5eGhKSldJZ05KbTUyTlppZllHaDNnYzNaakJVOVJhRXJLb0NidGVxdW1IWU9CSnN6RmNIUGFBPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
				}
			},
			"data": {
				"hash": {
					"algorithm": "sha256",
					"value":     "0c0f699f002f4de2ab43b04a0c930ceb57be35d2c81b31648d88b021713e9477"
				}
			}
		}
}`)

var entryBodyInvalid = []byte(`{
	"kind": "myRekorEntry",
	"apiVersion": "1.2.3",
	"mySpec": {}
}`)

var rootHash = []byte("deadbeef")

func TestNewTlogEntry(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		expectErr bool
	}{
		{
			name:      "rekor v2 hashedrekord",
			body:      entryBodyV2,
			expectErr: false,
		},
		{
			name:      "rekor v1 hashedrekord",
			body:      entryBodyV1,
			expectErr: false,
		},
		{
			name:      "unknown entry",
			body:      entryBodyInvalid,
			expectErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tle := v1.TransparencyLogEntry{
				LogIndex: 1,
				LogId: &protocommon.LogId{
					KeyId: []byte("logID"),
				},
				KindVersion: &v1.KindVersion{
					Kind:    "apple",
					Version: "alpha",
				},
				CanonicalizedBody: test.body,
				InclusionProof: &v1.InclusionProof{
					LogIndex: 1,
					TreeSize: 2,
					RootHash: rootHash,
					Checkpoint: &v1.Checkpoint{
						Envelope: string(rootHash),
					},
				},
			}
			_, err := NewTlogEntry(&tle)
			if test.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestParseTransparencyLogEntry(t *testing.T) {
	tle := v1.TransparencyLogEntry{
		LogIndex: 1,
		LogId: &protocommon.LogId{
			KeyId: []byte("logID"),
		},
		KindVersion: &v1.KindVersion{
			Kind:    "apple",
			Version: "alpha",
		},
		CanonicalizedBody: entryBodyV2,
		InclusionProof: &v1.InclusionProof{
			LogIndex: 1,
			TreeSize: 2,
			RootHash: rootHash,
			Checkpoint: &v1.Checkpoint{
				Envelope: string(rootHash),
			},
		},
	}
	_, err := ParseTransparencyLogEntry(&tle)
	assert.NoError(t, err)
}
