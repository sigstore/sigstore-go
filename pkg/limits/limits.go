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

package limits

// MaxAllowedTlogEntries bounds the number of transparency log entries processed
// from a bundle or entity; this is a defense-in-depth guard against DoS.
const MaxAllowedTlogEntries = 32

// MaxAllowedTimestamps bounds the number of signed timestamps processed from an
// entity; this is a defense-in-depth guard against DoS.
const MaxAllowedTimestamps = 32
