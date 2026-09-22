// Copyright 2024 The Sigstore Authors.
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

	commonV1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

const maxFuzzEntryInputSize = 64 * 1024

/*
FuzzParseEntry creates a randomized
TransparencyLogEntry and parses it
*/
func FuzzParseEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, proofTreeSize,
		proofLogIndex,
		tlEntryIntegratedTime,
		tlEntryIndex int64,
		proofRootHash,
		proofHash1,
		proofHash2,
		proofHash3,
		promiseSETimestamp,
		tlEntryCanonicalizedBody,
		logIdKeyId []byte,
		kindVersion,
		kindKind,
		checkpointEnvelope string) {
		// Parsing expands several fields through hex and JSON decoding. Keep the
		// aggregate work bounded when libFuzzer repeats a testcase many times.
		inputSize := len(proofRootHash) + len(proofHash1) + len(proofHash2) +
			len(proofHash3) + len(promiseSETimestamp) + len(tlEntryCanonicalizedBody) +
			len(logIdKeyId) + len(kindVersion) + len(kindKind) + len(checkpointEnvelope)
		if inputSize > maxFuzzEntryInputSize {
			t.Skip()
		}
		//nolint:errcheck
		ParseEntry(&v1.TransparencyLogEntry{
			LogIndex: tlEntryIndex,
			LogId: &commonV1.LogId{
				KeyId: logIdKeyId,
			},
			KindVersion: &v1.KindVersion{
				Kind:    kindKind,
				Version: kindVersion,
			},
			IntegratedTime: tlEntryIntegratedTime,
			InclusionPromise: &v1.InclusionPromise{
				SignedEntryTimestamp: promiseSETimestamp,
			},
			InclusionProof: &v1.InclusionProof{
				LogIndex: proofLogIndex,
				RootHash: proofRootHash,
				TreeSize: proofTreeSize,
				Hashes:   [][]byte{proofHash1, proofHash2, proofHash3},
				Checkpoint: &v1.Checkpoint{
					Envelope: checkpointEnvelope,
				},
			},
			CanonicalizedBody: tlEntryCanonicalizedBody,
		})
	})
}
