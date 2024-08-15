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

package bundle

import (
	"testing"
)

/*
FuzzBundle creates a randomized bundle and
invokes three of its methods
*/
//nolint:errcheck
func FuzzBundle(f *testing.F) {
	f.Fuzz(func(t *testing.T, bundleData []byte,
		call1,
		call2,
		call3 int,
		expectVersion string) {
		var bundle Bundle
		err := bundle.UnmarshalJSON(bundleData)
		if err != nil {
			t.Skip()
		}
		calls := []int{call1, call2, call3}
		for _, call := range calls {
			switch call % 8 {
			case 0:
				bundle.VerificationContent()
			case 1:
				bundle.HasInclusionPromise()
			case 2:
				bundle.HasInclusionProof()
			case 3:
				bundle.TlogEntries()
			case 4:
				bundle.SignatureContent()
			case 5:
				bundle.Envelope()
			case 6:
				bundle.Timestamps()
			case 7:
				bundle.MinVersion(expectVersion)
			}
		}
	})
}
