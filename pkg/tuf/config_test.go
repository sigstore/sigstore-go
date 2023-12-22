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

package tuf

import (
	"path/filepath"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	var p = filepath.Join(t.TempDir(), "cfg.json")
	var ts = time.Now()
	var c = Config{
		LastTimestamp: ts,
	}

	err := c.Persist(p)
	if err != nil {
		t.Error(err.Error())
	}

	cp, err := LoadConfig(p)
	delta := ts.Sub(cp.LastTimestamp)
	if delta < 0 {
		delta = -delta
	}
	// make sure the delta is less than one second. During JSON
	// serializion precision up to a second may be lost
	if delta > time.Second {
		t.Error("wrong date received after load")
	}
}
