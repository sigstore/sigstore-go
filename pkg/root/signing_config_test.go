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

package root

import (
	"reflect"
	"testing"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
)

func TestSigningConfig_FulcioCertificateAuthorityURL(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          string
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				CaUrl: "https://fulcio.sigstore.dev",
			},
			want: "https://fulcio.sigstore.dev",
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				CaUrl: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.FulcioCertificateAuthorityURL(); got != tt.want {
				t.Errorf("SigningConfig.FulcioCertificateAuthorityURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_OIDCProviderURL(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          string
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				OidcUrl: "https://oauth2.sigstore.dev/auth",
			},
			want: "https://oauth2.sigstore.dev/auth",
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				OidcUrl: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.OIDCProviderURL(); got != tt.want {
				t.Errorf("SigningConfig.OIDCProviderURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_RekorLogURLs(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          []string
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				TlogUrls: []string{"https://rekor.sigstore.dev", "https://2025.rekor.sigstore.dev"},
			},
			want: []string{"https://rekor.sigstore.dev", "https://2025.rekor.sigstore.dev"},
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				TlogUrls: []string{},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.RekorLogURLs(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SigningConfig.RekorLogURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_TimestampAuthorityURLs(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          []string
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				TsaUrls: []string{"https://tsa1.sigstore.dev", "https://tsa2.sigstore.dev"},
			},
			want: []string{"https://tsa1.sigstore.dev", "https://tsa2.sigstore.dev"},
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				TsaUrls: []string{},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.TimestampAuthorityURLs(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SigningConfig.TimestampAuthorityURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSigningConfig(t *testing.T) {
	type args struct {
		mediaType                  string
		fulcioCertificateAuthority string
		oidcProvider               string
		rekorLogs                  []string
		timestampAuthorities       []string
	}
	tests := []struct {
		name    string
		args    args
		want    *SigningConfig
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				mediaType:                  SigningConfigMediaType01,
				fulcioCertificateAuthority: "https://fulcio.sigstore.dev",
				oidcProvider:               "https://oauth2.sigstore.dev/auth",
				rekorLogs:                  []string{"https://rekor.sigstore.dev"},
				timestampAuthorities:       []string{"https://tsa.sigstore.dev"},
			},
			want: &SigningConfig{
				signingConfig: &prototrustroot.SigningConfig{
					MediaType: SigningConfigMediaType01,
					CaUrl:     "https://fulcio.sigstore.dev",
					OidcUrl:   "https://oauth2.sigstore.dev/auth",
					TlogUrls:  []string{"https://rekor.sigstore.dev"},
					TsaUrls:   []string{"https://tsa.sigstore.dev"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid media type",
			args: args{
				mediaType:                  "application/json",
				fulcioCertificateAuthority: "https://fulcio.sigstore.dev",
				oidcProvider:               "https://oauth2.sigstore.dev/auth",
				rekorLogs:                  []string{"https://rekor.sigstore.dev"},
				timestampAuthorities:       []string{"https://tsa.sigstore.dev"},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigningConfig(tt.args.mediaType, tt.args.fulcioCertificateAuthority, tt.args.oidcProvider, tt.args.rekorLogs, tt.args.timestampAuthorities)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigningConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigningConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
