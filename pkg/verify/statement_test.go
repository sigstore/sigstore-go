// Copyright 2026 The Sigstore Authors.
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

package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	in_toto "github.com/in-toto/attestation/go/v1"
)

// rawEnvelopeContent adapts a bare DSSE envelope to EnvelopeContent for
// exercising summarizeStatement. Statement() parses the full statement
// with protojson, mirroring the bundle package's implementation, so the
// summary can be compared against the canonical parse.
type rawEnvelopeContent struct {
	raw *dsse.Envelope
}

func (r *rawEnvelopeContent) RawEnvelope() *dsse.Envelope { return r.raw }

func (r *rawEnvelopeContent) Statement() (*in_toto.Statement, error) {
	payload, err := r.raw.DecodeB64Payload()
	if err != nil {
		return nil, err
	}
	var statement in_toto.Statement
	if err := protojson.Unmarshal(payload, &statement); err != nil {
		return nil, err
	}
	return &statement, nil
}

func envelopeWithPayload(t testing.TB, payloadType string, payload []byte) *rawEnvelopeContent {
	t.Helper()
	return &rawEnvelopeContent{raw: &dsse.Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
	}}
}

// statementJSON builds an in-toto statement document with the given
// number of subjects and a predicate of roughly predicateEntries keys.
func statementJSON(t testing.TB, subjects int, predicateEntries int) []byte {
	t.Helper()
	doc := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://example.dev/predicate/v1",
	}
	subs := make([]map[string]any, 0, subjects)
	for i := range subjects {
		subs = append(subs, map[string]any{
			"name": fmt.Sprintf("subject-%d", i),
			"digest": map[string]string{
				"sha256": fmt.Sprintf("%064d", i),
				"sha512": fmt.Sprintf("%0128d", i),
			},
		})
	}
	doc["subject"] = subs
	predicate := make(map[string]any, predicateEntries)
	for i := range predicateEntries {
		predicate[fmt.Sprintf("finding-%06d", i)] = map[string]any{
			"id":       fmt.Sprintf("VULN-%06d", i),
			"severity": "High",
			"detail":   "a moderately sized description string to give the predicate realistic weight",
		}
	}
	doc["predicate"] = predicate
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func TestSummarizeStatementMatchesFullParse(t *testing.T) {
	env := envelopeWithPayload(t, intotoMediaType, statementJSON(t, 3, 100))

	full, err := env.Statement()
	require.NoError(t, err)
	summary, err := summarizeStatement(env)
	require.NoError(t, err)

	assert.Equal(t, full.Type, summary.Type)
	assert.Equal(t, full.PredicateType, summary.PredicateType)
	require.Equal(t, len(full.Subject), len(summary.Subject))
	for i := range full.Subject {
		assert.Equal(t, full.Subject[i].Name, summary.Subject[i].Name)
		assert.Equal(t, full.Subject[i].Digest, summary.Subject[i].Digest)
	}

	// The full parse materializes the predicate; the summary never does.
	assert.NotNil(t, full.Predicate)
	assert.Nil(t, summary.Predicate)
}

func TestSummarizeStatementErrors(t *testing.T) {
	t.Run("unsupported payload type", func(t *testing.T) {
		env := envelopeWithPayload(t, "application/json", statementJSON(t, 1, 0))
		_, err := summarizeStatement(env)
		assert.ErrorContains(t, err, "unsupported DSSE payload type")
	})
	t.Run("invalid base64", func(t *testing.T) {
		env := &rawEnvelopeContent{raw: &dsse.Envelope{PayloadType: intotoMediaType, Payload: "!!!"}}
		_, err := summarizeStatement(env)
		assert.ErrorContains(t, err, "decoding DSSE payload")
	})
	t.Run("invalid JSON", func(t *testing.T) {
		env := envelopeWithPayload(t, intotoMediaType, []byte("{"))
		_, err := summarizeStatement(env)
		assert.ErrorContains(t, err, "parsing in-toto statement")
	})
	t.Run("nil envelope", func(t *testing.T) {
		_, err := summarizeStatement(&rawEnvelopeContent{})
		assert.ErrorContains(t, err, "no DSSE envelope")
	})
}

func TestWithoutStatementPredicate(t *testing.T) {
	cfg := &VerifierConfig{}
	require.NoError(t, WithoutStatementPredicate()(cfg))
	assert.True(t, cfg.omitStatementPredicate)
}

// BenchmarkStatementParse contrasts the full protojson statement parse
// with the verification summary on a statement whose predicate carries
// ~10k entries (about 1.4MiB of JSON) — representative of SBOM and
// vulnerability-report predicates.
func BenchmarkStatementParse(b *testing.B) {
	env := envelopeWithPayload(b, intotoMediaType, statementJSON(b, 2, 10000))

	b.Run("full", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := env.Statement(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("summary", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := summarizeStatement(env); err != nil {
				b.Fatal(err)
			}
		}
	})
}
