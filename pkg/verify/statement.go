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
	"encoding/json"
	"errors"
	"fmt"

	in_toto "github.com/in-toto/attestation/go/v1"
)

// intotoMediaType is the DSSE payload type carrying in-toto statements.
const intotoMediaType = "application/vnd.in-toto+json"

// summarizeStatement parses only the statement fields that verification
// consumes — the statement type, the subjects, and the predicate type —
// leaving the predicate itself unparsed (the returned Statement's
// Predicate is nil).
//
// Verification never reads the predicate, but predicates dominate
// statement size in many ecosystems (SBOMs, vulnerability reports, build
// provenance), sometimes by several orders of magnitude. Materializing
// them via protojson costs a structpb tree — one heap object per JSON
// node — which for megabyte-scale predicates allocates a large multiple
// of the payload size on every parse. Consumers that need the predicate
// still receive it on the verification result by default; this summary
// is for code paths that provably do not.
func summarizeStatement(envelope EnvelopeContent) (*in_toto.Statement, error) {
	raw := envelope.RawEnvelope()
	if raw == nil {
		return nil, errors.New("no DSSE envelope")
	}
	if raw.PayloadType != intotoMediaType {
		return nil, fmt.Errorf("unsupported DSSE payload type: %s", raw.PayloadType)
	}
	payload, err := raw.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}

	// protojson accepts both the JSON name and the proto field name for
	// every field, so "type" and "predicate_type" have to be read as well
	// as "_type" and "predicateType". Reading only the JSON names leaves
	// Type and PredicateType empty on a statement that the full parse
	// populates.
	var lite struct {
		Type               string `json:"_type"` //nolint:tagliatelle // in-toto statement field name
		ProtoType          string `json:"type"`
		PredicateType      string `json:"predicateType"`
		ProtoPredicateType string `json:"predicate_type"` //nolint:tagliatelle // proto field name
		Subject            []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &lite); err != nil {
		return nil, fmt.Errorf("parsing in-toto statement: %w", err)
	}

	statementType, err := pickSpelling("_type", lite.Type, "type", lite.ProtoType)
	if err != nil {
		return nil, fmt.Errorf("parsing in-toto statement: %w", err)
	}
	predicateType, err := pickSpelling("predicateType", lite.PredicateType, "predicate_type", lite.ProtoPredicateType)
	if err != nil {
		return nil, fmt.Errorf("parsing in-toto statement: %w", err)
	}

	statement := &in_toto.Statement{
		Type:          statementType,
		PredicateType: predicateType,
	}
	for _, s := range lite.Subject {
		statement.Subject = append(statement.Subject, &in_toto.ResourceDescriptor{
			Name:   s.Name,
			Digest: s.Digest,
		})
	}
	return statement, nil
}

// pickSpelling returns whichever of the two spellings of a field is set,
// rejecting a statement that carries both, the way protojson rejects a
// field given twice.
func pickSpelling(jsonName, jsonValue, protoName, protoValue string) (string, error) {
	switch {
	case jsonValue != "" && protoValue != "":
		return "", fmt.Errorf("statement sets both %q and %q", jsonName, protoName)
	case protoValue != "":
		return protoValue, nil
	default:
		return jsonValue, nil
	}
}
