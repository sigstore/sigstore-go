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

package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleV2_InterfaceMethods(t *testing.T) {
	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
				TransparencyLogProof: &bundleV2.TransparencyLogProof{
					Proof: []byte("proof"),
					Signature: &bundleV2.Signature{
						Signature: []byte("sig"),
					},
				},
			},
		},
	}

	b, err := NewBundleV2(pb)
	require.NoError(t, err)

	ver, err := b.Version()
	assert.NoError(t, err)
	assert.Equal(t, "v2.0", ver)

	assert.True(t, b.HasTransparencyLogProof())
	assert.False(t, b.HasCertificate())
	assert.False(t, b.HasPublicKey())
	assert.False(t, b.HasEnvelope())

	sig, err := b.Signature()
	assert.NoError(t, err)
	assert.Equal(t, []byte("sig"), sig)

	_, err = b.Envelope()
	assert.ErrorIs(t, err, ErrMissingEnvelope)

	_, _, err = b.Certificate()
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	tlogProof, err := b.TransparencyLogProof()
	assert.NoError(t, err)
	require.NotNil(t, tlogProof)
	assert.Equal(t, []byte("proof"), tlogProof.Proof)

	timestamps, err := b.Timestamps()
	assert.NoError(t, err)
	assert.Empty(t, timestamps)
}

func TestBundleV2_PublicKeyAndTimestamps(t *testing.T) {
	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_PublicKey{
				PublicKey: &bundleV2.PublicKey{
					Timestamps: &bundleV2.TimestampVerificationData{
						Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
							{SignedTimestamp: []byte("ts1")},
						},
					},
					Signature: &bundleV2.Signature{
						Signature: []byte("embedded-sig"),
					},
				},
			},
		},
		Payload: &bundleV2.Payload{
			PayloadType: IntotoMediaType,
			Payload:     []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
		},
	}

	b, err := NewBundleV2(pb)
	require.NoError(t, err)

	assert.False(t, b.HasTransparencyLogProof())
	assert.False(t, b.HasCertificate())
	assert.True(t, b.HasPublicKey())
	assert.True(t, b.HasEnvelope())

	_, _, err = b.Certificate()
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	_, err = b.TransparencyLogProof()
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	timestamps, err := b.Timestamps()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("ts1")}, timestamps)

	sig, err := b.Signature()
	require.NoError(t, err)
	assert.Equal(t, []byte("embedded-sig"), sig)

	env, err := b.Envelope()
	require.NoError(t, err)
	assert.NotNil(t, env)
}

func TestBundleV2_CertAndIntermediates(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	interCert, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	require.NoError(t, err)

	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_Certificate{
				Certificate: &bundleV2.Certificate{
					Certificate: &protocommon.X509Certificate{RawBytes: leafDER},
					Intermediates: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{{RawBytes: interDER}},
					},
					Timestamps: &bundleV2.TimestampVerificationData{
						Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
							{SignedTimestamp: []byte("cert-ts")},
						},
					},
					Signature: &bundleV2.Signature{Signature: []byte("sig")},
				},
			},
		},
	}

	b, err := NewBundleV2(pb)
	require.NoError(t, err)

	assert.False(t, b.HasTransparencyLogProof())
	assert.True(t, b.HasCertificate())
	assert.False(t, b.HasPublicKey())

	leaf, intermediates, err := b.Certificate()
	require.NoError(t, err)
	require.NotNil(t, leaf)
	assert.Equal(t, "leaf", leaf.Subject.CommonName)
	require.Len(t, intermediates, 1)
	assert.Equal(t, "intermediate", intermediates[0].Subject.CommonName)

	_, err = b.TransparencyLogProof()
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	timestamps, err := b.Timestamps()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("cert-ts")}, timestamps)

	// Self-signed intermediate should fail Certificate()
	pb.VerificationMaterial.GetCertificate().Intermediates.Certificates[0].RawBytes = rootDER
	_, _, err = b.Certificate()
	assert.ErrorIs(t, err, ErrValidation)

	// Non-CA intermediate should fail Certificate()
	pb.VerificationMaterial.GetCertificate().Intermediates.Certificates[0].RawBytes = leafDER
	_, _, err = b.Certificate()
	assert.ErrorIs(t, err, ErrValidation)
}

func TestBundleV2_ValidationErrors(t *testing.T) {
	_, err := NewBundleV2(nil)
	assert.ErrorIs(t, err, ErrEmptyBundle)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
	})
	assert.ErrorIs(t, err, ErrUnsupportedMediaType)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2+json",
	})
	assert.ErrorIs(t, err, ErrUnsupportedMediaType)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
	})
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		Payload:   &bundleV2.Payload{},
	})
	assert.ErrorIs(t, err, ErrMissingEnvelope)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
				TransparencyLogProof: &bundleV2.TransparencyLogProof{},
			},
		},
	})
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
				TransparencyLogProof: &bundleV2.TransparencyLogProof{
					Proof:     []byte("proof"),
					Signature: &bundleV2.Signature{},
				},
			},
		},
	})
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_PublicKey{
				PublicKey: &bundleV2.PublicKey{},
			},
		},
	})
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	_, err = NewBundleV2(&bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_Certificate{
				Certificate: &bundleV2.Certificate{
					Certificate: &protocommon.X509Certificate{RawBytes: []byte("cert")},
				},
			},
		},
	})
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)

	var emptyBundle BundleV2
	_, err = emptyBundle.TransparencyLogProof()
	assert.ErrorIs(t, err, ErrMissingVerificationMaterial)
}

func TestBundleV2_MarshalAndLoadJSONFromPathV2(t *testing.T) {
	pb := &bundleV2.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v2.0+json",
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
				TransparencyLogProof: &bundleV2.TransparencyLogProof{
					Proof: []byte("proof123"),
					Signature: &bundleV2.Signature{
						Signature: []byte("sig456"),
					},
				},
			},
		},
	}

	orig, err := NewBundleV2(pb)
	require.NoError(t, err)

	data, err := orig.MarshalJSON()
	require.NoError(t, err)

	tmpFile := filepath.Join(t.TempDir(), "bundle.json")
	err = os.WriteFile(tmpFile, data, 0600)
	require.NoError(t, err)

	b, err := LoadJSONFromPathV2(tmpFile)
	require.NoError(t, err)
	require.NotNil(t, b)
	assert.Equal(t, "application/vnd.dev.sigstore.bundle.v2.0+json", b.MediaType)

	ver, err := b.Version()
	assert.NoError(t, err)
	assert.Equal(t, "v2.0", ver)

	tlogProof, err := b.TransparencyLogProof()
	assert.NoError(t, err)
	require.NotNil(t, tlogProof)
	assert.Equal(t, []byte("proof123"), tlogProof.Proof)

	// Invalid JSON bundle on disk should fail validation in LoadJSONFromPathV2
	invalidFile := filepath.Join(t.TempDir(), "invalid.json")
	err = os.WriteFile(invalidFile, []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), 0600)
	require.NoError(t, err)
	_, err = LoadJSONFromPathV2(invalidFile)
	assert.ErrorIs(t, err, ErrUnsupportedMediaType)
}
