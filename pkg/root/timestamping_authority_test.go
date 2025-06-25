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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"
)

func TestTimestampingAuthority(t *testing.T) {
	privKey, rootCert, intermediateCert, leafCert, now := genChain(t, true)
	_, rootCert2, intermediateCert2, leafCert2, _ := genChain(t, true)

	artifactBytes := []byte("artifact")

	// generate a timestamping response
	tsrBytes, err := generateTimestampingResponse(artifactBytes, leafCert, privKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name          string
		tsa           *root.SigstoreTimestampingAuthority
		expectError   bool
		tsrBytes      []byte
		artifactBytes []byte
	}{
		{
			name: "normal",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf:                leafCert,
				ValidityPeriodStart: now.Add(-time.Hour),
				ValidityPeriodEnd:   now.Add(time.Hour),
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   false,
		},
		{
			name: "no validity period defined",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf: leafCert,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   false,
		},
		{
			name: "before validity period",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf:                leafCert,
				ValidityPeriodStart: now.Add(time.Hour),
				ValidityPeriodEnd:   now.Add(2 * time.Hour),
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "after validity period",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf:                leafCert,
				ValidityPeriodStart: now.Add(-2 * time.Hour),
				ValidityPeriodEnd:   now.Add(-time.Hour),
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "missing intermediate",
			tsa: &root.SigstoreTimestampingAuthority{
				Root:          rootCert,
				Intermediates: []*x509.Certificate{},
				Leaf:          leafCert,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "bad leaf",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf: leafCert2,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "bad intermediate",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert2,
				},
				Leaf: leafCert,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "bad root",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert2,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf: leafCert,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "nil root",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: nil,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf: leafCert,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: artifactBytes,
			expectError:   true,
		},
		{
			name: "signature over wrong artifact",
			tsa: &root.SigstoreTimestampingAuthority{
				Root: rootCert,
				Intermediates: []*x509.Certificate{
					intermediateCert,
				},
				Leaf: leafCert,
			},
			tsrBytes:      tsrBytes,
			artifactBytes: []byte("wrong artifact"),
			expectError:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			chains, err := test.tsa.Verify(test.tsrBytes, test.artifactBytes)
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

func generateTimestampingResponse(sig []byte, tsaCert *x509.Certificate, tsaKey *ecdsa.PrivateKey) ([]byte, error) {
	tsq, err := timestamp.CreateRequest(bytes.NewReader(sig), &timestamp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		return nil, err
	}

	req, err := timestamp.ParseRequest([]byte(tsq))
	if err != nil {
		return nil, err
	}

	tsTemplate := timestamp.Timestamp{
		HashAlgorithm:   req.HashAlgorithm,
		HashedMessage:   req.HashedMessage,
		Time:            time.Now(),
		Policy:          asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:        false,
		Qualified:       false,
		ExtraExtensions: req.Extensions,
	}

	return tsTemplate.CreateResponseWithOpts(tsaCert, tsaKey, crypto.SHA256)
}
