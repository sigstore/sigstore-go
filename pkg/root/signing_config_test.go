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
	"fmt"
	"reflect"
	"testing"
	"time"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Assume services are sorted such that they should match
func servicesEqual(got []Service, want []Service) bool {
	if len(got) != len(want) {
		return false
	}
	for i, g := range got {
		w := want[i]
		if g.URL != w.URL || g.MajorAPIVersion != w.MajorAPIVersion ||
			!g.ValidityPeriodStart.Equal(w.ValidityPeriodStart) ||
			!g.ValidityPeriodEnd.Equal(w.ValidityPeriodEnd) {
			return false
		}
	}
	return true
}

func newService(url string, now time.Time) Service {
	return Service{
		URL:                 url,
		MajorAPIVersion:     1,
		ValidityPeriodStart: now.Add(-time.Hour),
		ValidityPeriodEnd:   now.Add(time.Hour),
	}
}

func TestSelectService(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	farFuture := now.Add(2 * time.Hour)

	services := []Service{
		{
			URL:                 "url1",
			MajorAPIVersion:     1,
			ValidityPeriodStart: past,
			ValidityPeriodEnd:   future,
		},
		{
			URL:                 "url2",
			MajorAPIVersion:     2,
			ValidityPeriodStart: past,
			ValidityPeriodEnd:   future,
		},
		{
			URL:                 "url3_new",
			MajorAPIVersion:     2,
			ValidityPeriodStart: now,
			ValidityPeriodEnd:   future,
		},
		{
			URL:                 "url_no_end",
			MajorAPIVersion:     2,
			ValidityPeriodStart: farFuture,
			ValidityPeriodEnd:   time.Time{},
		},
	}

	tests := []struct {
		name               string
		services           []Service
		supportedVersions  uint32
		currentTime        time.Time
		expectedURL        string
		expectedErr        bool
		expectedErrMessage string
	}{
		{
			name:              "single matching service",
			services:          services,
			supportedVersions: 1,
			currentTime:       now,
			expectedURL:       "url1",
			expectedErr:       false,
		},
		{
			name:              "multiple matching service, first selected",
			services:          services,
			supportedVersions: 2,
			currentTime:       now,
			expectedURL:       "url2",
			expectedErr:       false,
		},
		{
			name:               "no matching version",
			services:           services,
			supportedVersions:  3,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "no matching service found for API versions [3] and current time",
		},
		{
			name:              "valid with no end time",
			services:          services,
			supportedVersions: 2,
			currentTime:       farFuture,
			expectedURL:       "url_no_end",
			expectedErr:       false,
		},
		{
			name:               "no matching service at all",
			services:           []Service{},
			supportedVersions:  1,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "no matching service found for API versions [1] and current time",
		},
		{
			name:              "first service selected when multiple match",
			services:          services,
			supportedVersions: 2,
			currentTime:       now.Add(time.Minute), // In the validity period of url3_new
			expectedURL:       "url2",
			expectedErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := SelectService(tt.services, []uint32{tt.supportedVersions}, tt.currentTime)
			if (err != nil) != tt.expectedErr {
				t.Errorf("SelectService() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
			if tt.expectedErr {
				if err.Error()[:len(tt.expectedErrMessage)] != tt.expectedErrMessage {
					t.Errorf("SelectService() error message = %v, expected %v", err.Error(), tt.expectedErrMessage)
				}
			} else if url != tt.expectedURL {
				t.Errorf("SelectService() got = %v, want %v", url, tt.expectedURL)
			}
		})
	}
}

func TestSelectServices(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	services := []Service{
		{
			URL:                 "url1",
			MajorAPIVersion:     1,
			ValidityPeriodStart: past,
			ValidityPeriodEnd:   future,
		},
		{
			URL:                 "url2",
			MajorAPIVersion:     2,
			ValidityPeriodStart: past,
			ValidityPeriodEnd:   future,
		},
		{
			URL:                 "url3",
			MajorAPIVersion:     2,
			ValidityPeriodStart: past,
			ValidityPeriodEnd:   future,
		},
	}

	tests := []struct {
		name               string
		services           []Service
		config             ServiceConfiguration
		supportedVersions  uint32
		currentTime        time.Time
		expectedURLs       []string
		possibleURLs       [][]string
		expectedErr        bool
		expectedErrMessage string
	}{
		{
			name:     "ALL selector, multiple matches",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_ALL,
			},
			supportedVersions: 2,
			currentTime:       now,
			expectedURLs:      []string{"url2", "url3"},
			expectedErr:       false,
		},
		{
			name:     "ALL selector, single match",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_ALL,
			},
			supportedVersions: 1,
			currentTime:       now,
			expectedURLs:      []string{"url1"},
			expectedErr:       false,
		},
		{
			name:     "ALL selector, no match",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_ALL,
			},
			supportedVersions:  3,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "no matching services found for API versions [3] and current time",
		},
		{
			name:     "ANY selector, multiple matches",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_ANY,
			},
			supportedVersions: 2,
			currentTime:       now,
			possibleURLs:      [][]string{{"url2"}, {"url3"}},
			expectedErr:       false,
		},
		{
			name:     "ANY selector, single match",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_ANY,
			},
			supportedVersions: 1,
			currentTime:       now,
			expectedURLs:      []string{"url1"},
			expectedErr:       false,
		},
		{
			name:     "ANY selector, no match",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_ANY,
			},
			supportedVersions:  3,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "no matching services found for API versions [3] and current time",
		},
		{
			name:     "EXACT selector, count 1, multiple matches",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    1,
			},
			supportedVersions: 2,
			currentTime:       now,
			possibleURLs:      [][]string{{"url2"}, {"url3"}},
			expectedErr:       false,
		},
		{
			name:     "EXACT selector, count 2, multiple matches",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    2,
			},
			supportedVersions: 2,
			currentTime:       now,
			possibleURLs:      [][]string{{"url2", "url3"}, {"url3", "url2"}},
			expectedErr:       false,
		},
		{
			name:     "EXACT selector, count 1, single match",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    1,
			},
			supportedVersions: 1,
			currentTime:       now,
			expectedURLs:      []string{"url1"},
			expectedErr:       false,
		},
		{
			name:     "EXACT selector, count 0",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    0,
			},
			supportedVersions:  2,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "service selector count must be greater than 0",
		},
		{
			name:     "EXACT selector, count greater than matches",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    3,
			},
			supportedVersions:  2,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "service selector count 3 must be less than or equal to the slice length 2",
		},
		{
			name:     "EXACT selector, count too hight",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    100,
			},
			supportedVersions:  2,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "service selector count 100 must be less than or equal to the slice length 2",
		},
		{
			name:     "EXACT selector, no matches",
			services: services,
			config: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    1,
			},
			supportedVersions:  3,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "no matching services found for API versions [3] and current time",
		},
		{
			name:     "Invalid selector",
			services: services,
			config: ServiceConfiguration{
				Selector: 99, // Invalid
			},
			supportedVersions:  2,
			currentTime:        now,
			expectedErr:        true,
			expectedErrMessage: "invalid service selector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, err := SelectServices(tt.services, tt.config, []uint32{tt.supportedVersions}, tt.currentTime)
			if (err != nil) != tt.expectedErr {
				t.Errorf("SelectServices() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
			if tt.expectedErr { //nolint:gocritic
				if err.Error()[:len(tt.expectedErrMessage)] != tt.expectedErrMessage {
					t.Errorf("SelectServices() error message = %v, expected %v", err.Error(), tt.expectedErrMessage)
				}
			} else if tt.possibleURLs != nil {
				// Handle EXACT and ANY tests, where results are random
				found := false
				for _, t := range tt.possibleURLs {
					if reflect.DeepEqual(urls, t) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("SelectServices() got = %v, wanted one of %v", urls, tt.possibleURLs)
				}
			} else if !reflect.DeepEqual(urls, tt.expectedURLs) {
				t.Errorf("SelectServices() got = %v, want %v", urls, tt.expectedURLs)
			}
		})
	}
}

func Test_selectExact(t *testing.T) {
	tests := []struct {
		name        string
		slice       []string
		count       uint32
		expectedErr bool
	}{
		{
			name:        "count 1",
			slice:       []string{"a", "b", "c"},
			count:       1,
			expectedErr: false,
		},
		{
			name:        "count 2",
			slice:       []string{"a", "b", "c"},
			count:       2,
			expectedErr: false,
		},
		{
			name:        "count equal to length",
			slice:       []string{"a", "b", "c"},
			count:       3,
			expectedErr: false,
		},
		{
			name:        "count 0",
			slice:       []string{"a", "b", "c"},
			count:       0,
			expectedErr: true,
		},
		{
			name:        "count greater than length",
			slice:       []string{"a", "b", "c"},
			count:       4,
			expectedErr: true,
		},
		{
			name:        "empty slice",
			slice:       []string{},
			count:       1,
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectExact(tt.slice, tt.count)
			if (err != nil) != tt.expectedErr {
				t.Errorf("selectExact() error = %v, wantErr %v", err, tt.expectedErr)
				return
			}
			if !tt.expectedErr && len(got) != int(tt.count) {
				t.Errorf("selectExact() got = %v", got)
			}
		})
	}
}

func Test_mapFunc(t *testing.T) {
	tests := []struct {
		name     string
		input    []int
		mapFn    func(int) string
		expected []string
	}{
		{
			name:     "simple mapping",
			input:    []int{1, 2, 3},
			mapFn:    func(i int) string { return fmt.Sprintf("num_%d", i) },
			expected: []string{"num_1", "num_2", "num_3"},
		},
		{
			name:     "empty slice",
			input:    []int{},
			mapFn:    func(i int) string { return fmt.Sprintf("num_%d", i) },
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapFunc(tt.input, tt.mapFn)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("mapFunc() got = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSigningConfig_FulcioCertificateAuthorityURLs(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          []Service
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				CaUrls: []*prototrustroot.Service{
					{
						Url:             "https://fulcio.sigstore.dev",
						MajorApiVersion: 1,
						ValidFor:        &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now)},
					},
				},
			},
			want: []Service{
				{
					URL:                 "https://fulcio.sigstore.dev",
					MajorAPIVersion:     1,
					ValidityPeriodStart: now,
					ValidityPeriodEnd:   now,
				},
			},
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				CaUrls: []*prototrustroot.Service{},
			},
			want: []Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.FulcioCertificateAuthorityURLs(); !servicesEqual(got, tt.want) {
				t.Errorf("SigningConfig.FulcioCertificateAuthorityURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_OIDCProviderURLs(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          []Service
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				OidcUrls: []*prototrustroot.Service{
					{
						Url:             "https://oauth2.sigstore.dev/auth",
						MajorApiVersion: 1,
						ValidFor:        &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now)},
					},
				},
			},
			want: []Service{
				{
					URL:                 "https://oauth2.sigstore.dev/auth",
					MajorAPIVersion:     1,
					ValidityPeriodStart: now,
					ValidityPeriodEnd:   now,
				},
			},
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				OidcUrls: []*prototrustroot.Service{},
			},
			want: []Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.OIDCProviderURLs(); !servicesEqual(got, tt.want) {
				t.Errorf("SigningConfig.OIDCProviderURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_RekorLogURLs(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          []Service
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				RekorTlogUrls: []*prototrustroot.Service{
					{
						Url:             "https://rekor.sigstore.dev",
						MajorApiVersion: 1,
						ValidFor:        &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now)},
					},
				},
			},
			want: []Service{
				{
					URL:                 "https://rekor.sigstore.dev",
					MajorAPIVersion:     1,
					ValidityPeriodStart: now,
					ValidityPeriodEnd:   now,
				},
			},
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				RekorTlogUrls: []*prototrustroot.Service{},
			},
			want: []Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.RekorLogURLs(); !servicesEqual(got, tt.want) {
				t.Errorf("SigningConfig.RekorLogURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_RekorLogURLsConfig(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          ServiceConfiguration
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				RekorTlogConfig: &prototrustroot.ServiceConfiguration{
					Selector: prototrustroot.ServiceSelector_EXACT,
					Count:    1,
				},
			},
			want: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    1,
			},
		},
		{
			name:          "empty",
			signingConfig: &prototrustroot.SigningConfig{RekorTlogConfig: &prototrustroot.ServiceConfiguration{}},
			want:          ServiceConfiguration{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.RekorLogURLsConfig(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SigningConfig.RekorLogURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_TimestampAuthorityURLs(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          []Service
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				TsaUrls: []*prototrustroot.Service{
					{
						Url:             "https://timestamp.sigstore.dev",
						MajorApiVersion: 1,
						ValidFor:        &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now)},
					},
				},
			},
			want: []Service{
				{
					URL:                 "https://timestamp.sigstore.dev",
					MajorAPIVersion:     1,
					ValidityPeriodStart: now,
					ValidityPeriodEnd:   now,
				},
			},
		},
		{
			name: "valid, unset end date",
			signingConfig: &prototrustroot.SigningConfig{
				TsaUrls: []*prototrustroot.Service{
					{
						Url:             "https://timestamp.sigstore.dev",
						MajorApiVersion: 1,
						ValidFor:        &v1.TimeRange{Start: timestamppb.New(now), End: nil},
					},
				},
			},
			want: []Service{
				{
					URL:                 "https://timestamp.sigstore.dev",
					MajorAPIVersion:     1,
					ValidityPeriodStart: now,
					ValidityPeriodEnd:   time.Time{},
				},
			},
		},
		{
			name: "empty",
			signingConfig: &prototrustroot.SigningConfig{
				TsaUrls: []*prototrustroot.Service{},
			},
			want: []Service{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.TimestampAuthorityURLs(); !servicesEqual(got, tt.want) {
				t.Errorf("SigningConfig.TimestampAuthorityURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigningConfig_TimestampAuthorityURLsConfig(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *prototrustroot.SigningConfig
		want          ServiceConfiguration
	}{
		{
			name: "valid",
			signingConfig: &prototrustroot.SigningConfig{
				TsaConfig: &prototrustroot.ServiceConfiguration{
					Selector: prototrustroot.ServiceSelector_EXACT,
					Count:    1,
				},
			},
			want: ServiceConfiguration{
				Selector: prototrustroot.ServiceSelector_EXACT,
				Count:    1,
			},
		},
		{
			name:          "empty",
			signingConfig: &prototrustroot.SigningConfig{TsaConfig: &prototrustroot.ServiceConfiguration{}},
			want:          ServiceConfiguration{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &SigningConfig{
				signingConfig: tt.signingConfig,
			}
			if got := sc.TimestampAuthorityURLsConfig(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SigningConfig.TimestampAuthorityURLsConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSigningConfig(t *testing.T) {
	now := time.Now()
	type args struct {
		mediaType                    string
		fulcioCertificateAuthorities []Service
		oidcProviders                []Service
		rekorLogs                    []Service
		timestampAuthorities         []Service
		config                       ServiceConfiguration
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
				mediaType:                    SigningConfigMediaType02,
				fulcioCertificateAuthorities: []Service{{URL: "https://fulcio.sigstore.dev", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				oidcProviders:                []Service{{URL: "https://oauth2.sigstore.dev/auth", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				rekorLogs:                    []Service{{URL: "https://rekor.sigstore.dev", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				timestampAuthorities:         []Service{{URL: "https://timestamp.sigstore.dev", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				config:                       ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
			},
			want: &SigningConfig{
				signingConfig: &prototrustroot.SigningConfig{
					MediaType:       SigningConfigMediaType02,
					CaUrls:          []*prototrustroot.Service{{Url: "https://fulcio.sigstore.dev", ValidFor: &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now.Add(time.Hour))}}},
					OidcUrls:        []*prototrustroot.Service{{Url: "https://oauth2.sigstore.dev/auth", ValidFor: &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now.Add(time.Hour))}}},
					RekorTlogUrls:   []*prototrustroot.Service{{Url: "https://rekor.sigstore.dev", ValidFor: &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now.Add(time.Hour))}}},
					RekorTlogConfig: &prototrustroot.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
					TsaUrls:         []*prototrustroot.Service{{Url: "https://timestamp.sigstore.dev", ValidFor: &v1.TimeRange{Start: timestamppb.New(now), End: timestamppb.New(now.Add(time.Hour))}}},
					TsaConfig:       &prototrustroot.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid media type",
			args: args{
				mediaType:                    "application/json",
				fulcioCertificateAuthorities: []Service{{URL: "https://fulcio.sigstore.dev", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				oidcProviders:                []Service{{URL: "https://oauth2.sigstore.dev/auth", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				rekorLogs:                    []Service{{URL: "https://rekor.sigstore.dev", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				timestampAuthorities:         []Service{{URL: "https://timestamp.sigstore.dev", ValidityPeriodStart: now, ValidityPeriodEnd: now.Add(time.Hour)}},
				config:                       ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigningConfig(tt.args.mediaType, tt.args.fulcioCertificateAuthorities, tt.args.oidcProviders, tt.args.rekorLogs, tt.args.config, tt.args.timestampAuthorities, tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigningConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil {
				if !servicesEqual(got.FulcioCertificateAuthorityURLs(), tt.want.FulcioCertificateAuthorityURLs()) {
					t.Errorf("NewSigningConfig.FulcioCertificateAuthorityURLs() = %v, want %v", got.FulcioCertificateAuthorityURLs(), tt.want.FulcioCertificateAuthorityURLs())
				}
				if !servicesEqual(got.OIDCProviderURLs(), tt.want.OIDCProviderURLs()) {
					t.Errorf("NewSigningConfig.OIDCProviderURLs() = %v, want %v", got.OIDCProviderURLs(), tt.want.OIDCProviderURLs())
				}
				if !servicesEqual(got.RekorLogURLs(), tt.want.RekorLogURLs()) {
					t.Errorf("NewSigningConfig.RekorLogURLs() = %v, want %v", got.RekorLogURLs(), tt.want.RekorLogURLs())
				}
				if !reflect.DeepEqual(got.RekorLogURLsConfig(), tt.want.RekorLogURLsConfig()) {
					t.Errorf("NewSigningConfig.RekorLogURLsConfig() = %v, want %v", got.RekorLogURLsConfig(), tt.want.RekorLogURLsConfig())
				}
				if !servicesEqual(got.TimestampAuthorityURLs(), tt.want.TimestampAuthorityURLs()) {
					t.Errorf("NewSigningConfig.TimestampAuthorityURLs() = %v, want %v", got.TimestampAuthorityURLs(), tt.want.TimestampAuthorityURLs())
				}
				if !reflect.DeepEqual(got.TimestampAuthorityURLsConfig(), tt.want.TimestampAuthorityURLsConfig()) {
					t.Errorf("NewSigningConfig.TimestampAuthorityURLsConfig() = %v, want %v", got.TimestampAuthorityURLsConfig(), tt.want.TimestampAuthorityURLsConfig())
				}
			}
		})
	}
}

func TestNewSigningConfigWithOptions(t *testing.T) {
	now := time.Now()
	expectedCAService := newService("ca-url", now)
	expectedOIDCService := newService("oidc-url", now)
	expectedRekorLogService := newService("rekor-url", now)
	expectedTSAService := newService("tsa-url", now)
	sc, err := NewSigningConfig(SigningConfigMediaType02, nil, nil, nil, ServiceConfiguration{}, nil, ServiceConfiguration{})
	sc = sc.WithFulcioCertificateAuthorityURLs(expectedCAService).
		WithOIDCProviderURLs(expectedOIDCService).
		WithRekorLogURLs(expectedRekorLogService).
		WithTimestampAuthorityURLs(expectedTSAService).
		WithRekorTlogConfig(prototrustroot.ServiceSelector_EXACT, 1).
		WithTsaConfig(prototrustroot.ServiceSelector_EXACT, 1)
	if err != nil {
		t.Errorf("NewSigningConfig() error = %v", err)
	}
	if !servicesEqual(sc.FulcioCertificateAuthorityURLs(), []Service{expectedCAService}) {
		t.Errorf("unexpected CA service, expected %v, got %v", expectedCAService, sc.FulcioCertificateAuthorityURLs())
	}
	if !servicesEqual(sc.OIDCProviderURLs(), []Service{expectedOIDCService}) {
		t.Errorf("unexpected OIDC service, expected %v, got %v", expectedOIDCService, sc.OIDCProviderURLs())
	}
	if !servicesEqual(sc.RekorLogURLs(), []Service{expectedRekorLogService}) {
		t.Errorf("unexpected Rekor service, expected %v, got %v", expectedRekorLogService, sc.RekorLogURLs())
	}
	if !servicesEqual(sc.TimestampAuthorityURLs(), []Service{expectedTSAService}) {
		t.Errorf("unexpected TSA service, expected %v, got %v", expectedTSAService, sc.TimestampAuthorityURLs())
	}
	if !reflect.DeepEqual(sc.RekorLogURLsConfig(), ServiceConfiguration{Selector: prototrustroot.ServiceSelector_EXACT, Count: 1}) {
		t.Errorf("unexpected Rekor config, expected %v", sc.RekorLogURLsConfig())
	}
	if !reflect.DeepEqual(sc.TimestampAuthorityURLsConfig(), ServiceConfiguration{Selector: prototrustroot.ServiceSelector_EXACT, Count: 1}) {
		t.Errorf("unexpected TSA config, expected %v", sc.TimestampAuthorityURLsConfig())
	}

	expectedAddedCAService := newService("ca-url2", now)
	expectedAddedOIDCService := newService("oidc-url2", now)
	expectedAddedRekorLogService := newService("rekor-url2", now)
	expectedAddedTSAService := newService("tsa-url2", now)

	sc = sc.AddFulcioCertificateAuthorityURLs(expectedAddedCAService).AddOIDCProviderURLs(expectedAddedOIDCService).
		AddRekorLogURLs(expectedAddedRekorLogService).AddTimestampAuthorityURLs(expectedAddedTSAService)
	if !servicesEqual(sc.FulcioCertificateAuthorityURLs(), []Service{expectedCAService, expectedAddedCAService}) {
		t.Errorf("unexpected CA service, expected %v, got %v", expectedCAService, sc.FulcioCertificateAuthorityURLs())
	}
	if !servicesEqual(sc.OIDCProviderURLs(), []Service{expectedOIDCService, expectedAddedOIDCService}) {
		t.Errorf("unexpected OIDC service, expected %v, got %v", expectedOIDCService, sc.OIDCProviderURLs())
	}
	if !servicesEqual(sc.RekorLogURLs(), []Service{expectedRekorLogService, expectedAddedRekorLogService}) {
		t.Errorf("unexpected Rekor service, expected %v, got %v", expectedRekorLogService, sc.RekorLogURLs())
	}
	if !servicesEqual(sc.TimestampAuthorityURLs(), []Service{expectedTSAService, expectedAddedTSAService}) {
		t.Errorf("unexpected TSA service, expected %v, got %v", expectedTSAService, sc.TimestampAuthorityURLs())
	}
}
