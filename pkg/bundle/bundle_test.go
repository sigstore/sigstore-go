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

package bundle

import (
	"fmt"
	"testing"
)

func Test_getBundleVersion(t *testing.T) {
	tests := []struct {
		mediaType string
		want      string
		wantErr   bool
	}{
		{
			mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
			want:      "v0.1",
			wantErr:   false,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
			want:      "v0.2",
			wantErr:   false,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
			want:      "v0.3",
			wantErr:   false,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
			want:      "v0.3",
			wantErr:   false,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle.v0.3.1+json",
			want:      "v0.3.1",
			wantErr:   false,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle.v0.4+json",
			want:      "v0.4",
			wantErr:   false,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle+json",
			want:      "",
			wantErr:   true,
		},
		{
			mediaType: "garbage",
			want:      "",
			wantErr:   true,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle.vgarbage+json",
			want:      "",
			wantErr:   true,
		},
		{
			mediaType: "application/vnd.dev.sigstore.bundle.v0.3.1.1.1.1+json",
			want:      "",
			wantErr:   true,
		},
		{
			mediaType: "",
			want:      "",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("mediatype:%s", tt.mediaType), func(t *testing.T) {
			got, err := getBundleVersion(tt.mediaType)
			if (err != nil) != tt.wantErr {
				t.Errorf("getBundleVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getBundleVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
