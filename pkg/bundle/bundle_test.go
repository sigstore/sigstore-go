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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekorv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/stretchr/testify/require"
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

func TestMinVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		mediaType       string
		expectedVersion string
		ret             bool
	}{
		{"old-format", "application/vnd.dev.sigstore.bundle+json;version=0.1", "v0.1", true},
		{"old-format-unexpected", "application/vnd.dev.sigstore.bundle+json;version=0.1", "v0.2", false},
		{"old-format-without-v", "application/vnd.dev.sigstore.bundle+json;version=0.1", "0.1", true},
		{"new-format", "application/vnd.dev.sigstore.bundle.v0.3+json", "v0.1", true},
		{"new-format-exact", "application/vnd.dev.sigstore.bundle.v0.3+json", "v0.3", true},
		{"new-format-unexpected", "application/vnd.dev.sigstore.bundle.v0.2+json", "v0.3", false},
		{"new-format-without-v", "application/vnd.dev.sigstore.bundle.v0.3+json", "0.3", true},
		{"new-format-without-v-unexpected", "application/vnd.dev.sigstore.bundle.v0.2+json", "0.3", false},
		{"blank", "", "", false},
		{"invalid", "garbage", "v0.1", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &Bundle{Bundle: &protobundle.Bundle{
				MediaType: tc.mediaType,
			}}
			ret := b.MinVersion(tc.expectedVersion)
			if tc.ret != ret {
				t.Fatalf("expected %v, got %v", tc.ret, ret)
			}
		})
	}
}

func TestMediaTypeString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		ver      string
		expected string
		mustErr  bool
	}{
		{"normal-semver", "v0.3", "application/vnd.dev.sigstore.bundle.v0.3+json", false},
		{"old-semver1", "v0.1", "application/vnd.dev.sigstore.bundle+json;version=0.1", false},
		{"old-semver2", "v0.2", "application/vnd.dev.sigstore.bundle+json;version=0.2", false},
		{"blank", "", "", true},
		{"invalid", "garbage", "", true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := MediaTypeString(tc.ver)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, res)
		})
	}
}

func Test_validate(t *testing.T) {
	t.Parallel()
	tlogBody := map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"signature": map[string]any{
				"content": "sn/VqLMqWjDeYt93XTb6LzWIsKIn5bOvEsZQyF1elkvpur85LoDk5q/ExGWBB0Y+v8q0B04Bg2xGMOVMNyD/LQ==",
				"publicKey": map[string]any{
					"content": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJnekNDQVMyZ0F3SUJBZ0lVS2cxZHN1OTBoS0daVW5WN1RRWFZPRjdOZCtrd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0ZqRVVNQklHQTFVRUF3d0xhblZ6ZEhSeWRYTjBiV1V3SGhjTk1qUXdOakkwTWpJMU5USXpXaGNOTXpRdwpOakl5TWpJMU5USXpXakFXTVJRd0VnWURWUVFEREF0cWRYTjBkSEoxYzNSdFpUQmNNQTBHQ1NxR1NJYjNEUUVCCkFRVUFBMHNBTUVnQ1FRRGIwNjhSMkpYNStZSE5nZWVyeDlzM1k2eEp2ZVdPRGl3YnROZWtKaytTWUlDUjNYQlQKaDErNUJ1SStwTGNyTXNyQTZlOThaNkNxUkJjNDdEL05LdWgvQWdNQkFBR2pVekJSTUIwR0ExVWREZ1FXQkJTbgpKbExuNWZjeXYzNnlibHBKYTVkcmdhQlNBREFmQmdOVkhTTUVHREFXZ0JTbkpsTG41ZmN5djM2eWJscEphNWRyCmdhQlNBREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUEwRUFaaTNCMTF4VDY5TjQKNnl4ODg5Rkl2Z0xIdjQvaUROR2JTUkpHanlXMXY1RFpscXBBT0dYWjc5V3d2TFJZQlAxbFhid0tGaGlzTlNsUwpNRk84c0FHZ1hRPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
				},
			},
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     "bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b",
				},
			},
		},
	}
	canonicalTlogBody, err := json.Marshal(tlogBody)
	require.NoError(t, err)
	tests := []struct {
		name    string
		pb      Bundle
		wantErr bool
	}{
		{
			name: "invalid media type",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "",
				},
			},
			wantErr: true,
		},
		{
			name: "version too low",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle.v0.0.1+json",
				},
			},
			wantErr: true,
		},
		{
			name: "version too high",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.4",
				},
			},
			wantErr: true,
		},
		{
			name: "no verification material",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				},
			},
			wantErr: true,
		},
		{
			name: "v0.1 with no inclusion promise",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "v0.1 with inclusion promise",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionPromise: &rekorv1.InclusionPromise{
									SignedEntryTimestamp: []byte("1"),
								},
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
		},
		{
			name: "v0.1 with inclusion promise & proof without checkpoint",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex: 42,
									RootHash: []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
								},
								InclusionPromise: &rekorv1.InclusionPromise{
									SignedEntryTimestamp: []byte("1"),
								},
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
			wantErr: true,
		},
		{
			name: "v0.1 with inclusion proof & promise",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex:   42,
									RootHash:   []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
									Checkpoint: &rekorv1.Checkpoint{Envelope: "checkpoint"},
								},
								InclusionPromise: &rekorv1.InclusionPromise{
									SignedEntryTimestamp: []byte("1"),
								},
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
		},
		{
			name: "v0.2 with no inclusion proof",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
			wantErr: true,
		},
		{
			name: "v0.2 with inclusion proof without checkpoint",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex: 42,
									RootHash: []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
								},
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
			wantErr: true,
		},
		{
			name: "v0.2 with inclusion proof with empty checkpoint",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex:   42,
									RootHash:   []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
									Checkpoint: &rekorv1.Checkpoint{},
								},
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
			wantErr: true,
		},
		{
			name: "v0.2 with inclusion proof",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex:   42,
									RootHash:   []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
									Checkpoint: &rekorv1.Checkpoint{Envelope: "checkpoint"},
								},
							},
						},
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
		},
		{
			name: "v0.3 with x.509 certificate chain",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex:   42,
									RootHash:   []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
									Checkpoint: &rekorv1.Checkpoint{Envelope: "checkpoint"},
								},
							},
						},
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
			wantErr: true,
		},
		{
			name: "v0.3 without x.509 certificate chain",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
					VerificationMaterial: &protobundle.VerificationMaterial{
						TlogEntries: []*rekorv1.TransparencyLogEntry{
							{
								LogIndex: 42,
								LogId: &protocommon.LogId{
									KeyId: []byte("deadbeef"),
								},
								KindVersion: &rekorv1.KindVersion{
									Kind:    "hashedrekord",
									Version: "0.0.1",
								},
								IntegratedTime:    1,
								CanonicalizedBody: canonicalTlogBody,
								InclusionProof: &rekorv1.InclusionProof{
									LogIndex:   42,
									RootHash:   []byte("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
									Checkpoint: &rekorv1.Checkpoint{Envelope: "checkpoint"},
								},
							},
						},
						Content: &protobundle.VerificationMaterial_Certificate{
							Certificate: &protocommon.X509Certificate{},
						},
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pb.validate()
			if (got != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr = %v", got, tt.wantErr)
			}
		})
	}
}

func TestVerificationContent(t *testing.T) {
	t.Parallel()
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	leafCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 512) //nolint:gosec
	require.NoError(t, err)
	leafKey, err := rsa.GenerateKey(rand.Reader, 512) //nolint:gosec
	require.NoError(t, err)
	caDer, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	leafDer, err := x509.CreateCertificate(rand.Reader, leafCert, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	tests := []struct {
		name            string
		pb              Bundle
		wantCertificate bool
		wantPublicKey   bool
		wantErr         bool
	}{
		{
			name: "no verification material",
			pb: Bundle{
				Bundle: &protobundle.Bundle{},
			},
			wantErr: true,
		},
		{
			name: "certificate chain with zero certs",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate chain with self-signed cert",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{
								Certificates: []*protocommon.X509Certificate{
									{
										RawBytes: caDer,
									},
								},
							},
						},
					},
				},
			},
			wantCertificate: true,
		},
		{
			name: "certificate chain",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{
								Certificates: []*protocommon.X509Certificate{
									{
										RawBytes: leafDer,
									},
									{
										RawBytes: caDer,
									},
								},
							},
						},
					},
				},
			},
			wantCertificate: true,
		},
		{
			name: "certificate chain with invalid cert",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{
								Certificates: []*protocommon.X509Certificate{
									{
										RawBytes: []byte("hello"),
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate chain with nil bytes",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{
								Certificates: []*protocommon.X509Certificate{
									{
										RawBytes: nil,
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate chain with nil cert",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: &protocommon.X509CertificateChain{
								Certificates: nil,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate chain with nil chain",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_X509CertificateChain{
							X509CertificateChain: nil,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_Certificate{
							Certificate: &protocommon.X509Certificate{
								RawBytes: leafDer,
							},
						},
					},
				},
			},
			wantCertificate: true,
		},
		{
			name: "invalid certificate",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_Certificate{
							Certificate: &protocommon.X509Certificate{
								RawBytes: []byte("hello"),
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "certificate with nil bytes",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_Certificate{
							Certificate: &protocommon.X509Certificate{
								RawBytes: nil,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty certificate",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_Certificate{
							Certificate: &protocommon.X509Certificate{
								RawBytes: nil,
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "public key",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
					},
				},
			},
			wantPublicKey: true,
		},
		{
			name: "nil public key",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: nil,
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.pb.VerificationContent()
			if tt.wantErr {
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, gotErr)
			if tt.wantCertificate {
				require.NotNil(t, got.Certificate())
				return
			}
			if tt.wantPublicKey {
				k := got.PublicKey()
				require.NotNil(t, k)
				return
			}
		})
	}
}

func TestSignatureContent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pb            Bundle
		wantEnvelope  bool
		wantSignature bool
		wantErr       bool
	}{
		{
			name: "dsse envelope",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_DsseEnvelope{
						DsseEnvelope: &protodsse.Envelope{
							Payload:    []byte{},
							Signatures: []*protodsse.Signature{{Sig: []byte{}, Keyid: ""}},
						},
					},
				},
			},
			wantEnvelope: true,
		},
		{
			name: "dsse envelope with nil signature",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_DsseEnvelope{
						DsseEnvelope: &protodsse.Envelope{
							Payload:    []byte{},
							Signatures: []*protodsse.Signature{nil},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "dsse envelope with nil payload",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_DsseEnvelope{
						DsseEnvelope: &protodsse.Envelope{
							Payload:    nil,
							Signatures: []*protodsse.Signature{{Sig: []byte{}, Keyid: ""}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "message signature",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_MessageSignature{
						MessageSignature: &protocommon.MessageSignature{
							MessageDigest: &protocommon.HashOutput{},
						},
					},
				},
			},
			wantSignature: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.pb.SignatureContent()
			if tt.wantErr {
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, gotErr)
			if tt.wantEnvelope {
				require.NotNil(t, got.EnvelopeContent())
				return
			}
			if tt.wantSignature {
				require.NotNil(t, got.MessageSignatureContent())
				return
			}
		})
	}
}

func TestEnvelope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pb      Bundle
		wantErr bool
	}{
		{
			name: "dsse envelope",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_DsseEnvelope{
						DsseEnvelope: &protodsse.Envelope{
							Payload:    []byte{},
							Signatures: []*protodsse.Signature{{Sig: []byte{}, Keyid: ""}},
						},
					},
				},
			},
		},
		{
			name: "message signature",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_MessageSignature{
						MessageSignature: &protocommon.MessageSignature{
							MessageDigest: &protocommon.HashOutput{},
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := tt.pb.Envelope()
			if tt.wantErr {
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, gotErr)
		})
	}
}

func TestTimestamps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		pb             Bundle
		wantTimestamps [][]byte
		wantErr        bool
	}{
		{
			name:    "missing verification material",
			pb:      Bundle{Bundle: &protobundle.Bundle{}},
			wantErr: true,
		},
		{
			name: "empty timestamp data",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{},
				},
			},
			wantTimestamps: make([][]byte, 0),
		},
		{
			name: "one timestamp",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						TimestampVerificationData: &protobundle.TimestampVerificationData{
							Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
								{
									SignedTimestamp: []byte("sometime yesterday"),
								},
							},
						},
					},
				},
			},
			wantTimestamps: [][]byte{
				[]byte("sometime yesterday"),
			},
		},
		{
			name: "multiple timestamps",
			pb: Bundle{
				Bundle: &protobundle.Bundle{
					VerificationMaterial: &protobundle.VerificationMaterial{
						TimestampVerificationData: &protobundle.TimestampVerificationData{
							Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
								{
									SignedTimestamp: []byte("sometime yesterday"),
								},
								{
									SignedTimestamp: []byte("last week"),
								},
							},
						},
					},
				},
			},
			wantTimestamps: [][]byte{
				[]byte("sometime yesterday"),
				[]byte("last week"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.pb.Timestamps()
			if tt.wantErr {
				require.Error(t, gotErr)
				return
			}
			require.NoError(t, gotErr)
			require.Equal(t, tt.wantTimestamps, got)
		})
	}
}

func Test_BundleValidation(t *testing.T) {
	tests := []struct {
		name    string
		bundle  *Bundle
		errMsg  string
		wantErr bool
	}{
		{
			name: "Empty verification material",
			bundle: &Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: nil,
					},
					Content: &protobundle.Bundle_MessageSignature{},
				},
			},
			errMsg:  "invalid bundle: validation error: missing verification material",
			wantErr: true,
		},
		{
			name: "No bundle content",
			bundle: &Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
					Content:   nil,
				},
			},
			errMsg:  "invalid bundle: validation error: missing bundle content",
			wantErr: true,
		},
		{
			name: "Nil verification material",
			bundle: &Bundle{
				Bundle: &protobundle.Bundle{
					MediaType:            "application/vnd.dev.sigstore.bundle+json;version=0.3",
					Content:              &protobundle.Bundle_MessageSignature{},
					VerificationMaterial: nil,
				},
			},
			errMsg:  "invalid bundle: validation error: missing verification material",
			wantErr: true,
		},
		{
			name: "Valid protobuf bundle",
			bundle: &Bundle{
				Bundle: &protobundle.Bundle{
					MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
					Content:   &protobundle.Bundle_DsseEnvelope{},
					VerificationMaterial: &protobundle.VerificationMaterial{
						Content: &protobundle.VerificationMaterial_PublicKey{
							PublicKey: &protocommon.PublicKeyIdentifier{},
						},
						TimestampVerificationData: &protobundle.TimestampVerificationData{},
					},
				},
			},
			errMsg:  "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("name:%s", tt.name), func(t *testing.T) {
			err := tt.bundle.validate()
			if (err != nil) != tt.wantErr || (err != nil && tt.errMsg != err.Error()) {
				t.Errorf("Protobuf.Bundle() error = %v, wantErr %v", err, tt.errMsg)
				return
			}
		})
	}
}
