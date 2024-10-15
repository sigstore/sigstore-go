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

package root_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	tsx509 "github.com/sigstore/timestamp-authority/pkg/x509"
	"github.com/stretchr/testify/require"
)

func TestCertificateAuthority(t *testing.T) {
	_, rootCert, intermediateCert, leafCert, now := genChain(t, false)
	_, rootCert2, intermediateCert2, leafCert2, _ := genChain(t, false)

	for _, test := range []struct {
		name        string
		ca          *root.FulcioCertificateAuthority
		expectError bool
		leafCert    *x509.Certificate
	}{
		{
			name: "normal",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
			leafCert:    leafCert,
			expectError: false,
		},
		{
			name: "no validity period defined",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
			},
			leafCert:    leafCert,
			expectError: false,
		},
		{
			name: "before validity period",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				ValidityPeriodStart: now.Add(time.Hour),
			},
			leafCert:    leafCert,
			expectError: true,
		},
		{
			name: "after validity period",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				ValidityPeriodEnd: now.Add(-time.Hour),
			},
			leafCert:    leafCert,
			expectError: true,
		},
		{
			name: "missing intermediate",
			ca: &root.FulcioCertificateAuthority{
				Root:                rootCert,
				Intermediates:       []*x509.Certificate{},
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
			leafCert:    leafCert,
			expectError: true,
		},
		{
			name: "bad leaf",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
			leafCert:    leafCert2,
			expectError: true,
		},
		{
			name: "bad intermediate",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert2,
				},
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
			leafCert:    leafCert,
			expectError: true,
		},
		{
			name: "bad root",
			ca: &root.FulcioCertificateAuthority{
				Root: rootCert2,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
			leafCert:    leafCert,
			expectError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			chains, err := test.ca.Verify(test.leafCert, now)
			if test.expectError {
				require.Error(t, err)
				require.Nil(t, chains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, chains)
			}
		})
	}
}

func genChain(t *testing.T, tsa bool) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, *x509.Certificate, time.Time) {
	now := time.Now()

	rootCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	intermediateCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	leafCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		NotBefore:    now,
		NotAfter:     now.Add(10 * time.Minute),
	}
	if tsa {
		rootCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		intermediateCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		leafCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{tsx509.EKUTimestampingOID})
		if err != nil {
			t.Fatal(err)
		}
		leafCertTemplate.ExtraExtensions = []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //nolint:gosec
	require.NoError(t, err)
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //nolint:gosec
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) //nolint:gosecec
	require.NoError(t, err)
	rootDer, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	intermediateDer, err := x509.CreateCertificate(rand.Reader, intermediateCertTemplate, rootCertTemplate, &intermediateKey.PublicKey, caKey)
	require.NoError(t, err)
	leafDer, err := x509.CreateCertificate(rand.Reader, leafCertTemplate, intermediateCertTemplate, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)
	intermediateCert, err := x509.ParseCertificate(intermediateDer)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDer)
	require.NoError(t, err)

	return leafKey, rootCert, intermediateCert, leafCert, now
}
