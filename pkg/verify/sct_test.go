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

package verify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
)

func TestVerifySignedCertificateTimestamp(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	anotherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	skid, err := cryptoutils.SKID(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	anotherSKID, err := cryptoutils.SKID(&anotherPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert := createBaseCert(t, privateKey, skid, big.NewInt(1))
	anotherCACert := createBaseCert(t, anotherPrivateKey, anotherSKID, big.NewInt(99))
	logID, err := ctfe.GetCTLogID(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name            string
		getCertFn       func() *x509.Certificate
		threshold       int
		trustedMaterial root.TrustedMaterial
		wantErr         bool
	}{
		{
			name:            "missing sct in cert",
			getCertFn:       func() *x509.Certificate { return createBaseCert(t, privateKey, skid, big.NewInt(1)) },
			threshold:       1,
			trustedMaterial: &fakeTrustedMaterial{},
			wantErr:         true,
		},
		{
			name: "sct missing from ct logs",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{{
					SCTVersion: ct.V1,
					Timestamp:  12345,
					LogID:      ct.LogID{KeyID: logID},
				}})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{},
			},
			wantErr: true,
		},
		{
			name: "missing fulcio CAs",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{{
					SCTVersion: ct.V1,
					Timestamp:  12345,
					LogID:      ct.LogID{KeyID: logID},
				}})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {},
				},
			},
			wantErr: true,
		},
		{
			name: "one valid sct",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{{
					SCTVersion: ct.V1,
					Timestamp:  12345,
					LogID:      ct.LogID{KeyID: logID},
				}})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "one invalid sct",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: [32]byte{1, 2, 3, 4}},
					},
				})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "one valid sct out of multiple invalid scts",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: logID},
					},
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: [32]byte{1, 2, 3, 4}},
					},
				})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "threshold of 2 with only 1 valid sct",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: logID},
					},
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: [32]byte{1, 2, 3, 4}},
					},
				})
			},
			threshold: 2,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no valid scts out of multiple",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: [32]byte{0, 1, 2, 3}},
					},
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: [32]byte{4, 5, 6, 7}},
					},
				})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "fulcio CA has intermediates",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{{
					SCTVersion: ct.V1,
					Timestamp:  12345,
					LogID:      ct.LogID{KeyID: logID},
				}})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
						Intermediates: []*x509.Certificate{
							caCert,
						},
					},
				},
			},
		},
		{
			name: "no valid fulcio CAs",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{{
					SCTVersion: ct.V1,
					Timestamp:  12345,
					LogID:      ct.LogID{KeyID: logID},
				}})
			},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: anotherCACert,
					},
				},
			},
			wantErr: true,
		},
		{
			name:            "threshold of 0",
			getCertFn:       func() *x509.Certificate { return createBaseCert(t, privateKey, skid, big.NewInt(1)) },
			threshold:       0,
			trustedMaterial: &fakeTrustedMaterial{},
		},
		{
			name: "threshold of 2 with 2 valid scts",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []ct.SignedCertificateTimestamp{
					{
						SCTVersion: ct.V1,
						Timestamp:  12345,
						LogID:      ct.LogID{KeyID: logID},
					},
					{
						SCTVersion: ct.V1,
						Timestamp:  99,
						LogID:      ct.LogID{KeyID: logID},
					},
				})
			},
			threshold: 2,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					{
						Root: caCert,
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err = VerifySignedCertificateTimestamp(test.getCertFn(), test.threshold, test.trustedMaterial)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func createBaseCert(t *testing.T, privateKey *rsa.PrivateKey, skid []byte, serialNumber *big.Int) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		SubjectKeyId: skid,
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCert
}

func embedSCTs(t *testing.T, privateKey *rsa.PrivateKey, skid []byte, preCert *x509.Certificate, sctInput []ct.SignedCertificateTimestamp) *x509.Certificate {
	scts := make([]*ct.SignedCertificateTimestamp, 0)
	for _, s := range sctInput {
		logEntry := ct.LogEntry{
			Leaf: ct.MerkleTreeLeaf{
				Version:  ct.V1,
				LeafType: ct.TimestampedEntryLeafType,
				TimestampedEntry: &ct.TimestampedEntry{
					Timestamp: s.Timestamp,
					EntryType: ct.PrecertLogEntryType,
					PrecertEntry: &ct.PreCert{
						IssuerKeyHash:  sha256.Sum256(preCert.RawSubjectPublicKeyInfo),
						TBSCertificate: preCert.RawTBSCertificate,
					},
				},
			},
		}
		data, err := ct.SerializeSCTSignatureInput(s, logEntry)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(data)
		signature, err := privateKey.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		sct := ct.SignedCertificateTimestamp{
			SCTVersion: s.SCTVersion,
			LogID:      s.LogID,
			Timestamp:  s.Timestamp,
			Signature: ct.DigitallySigned{
				Algorithm: tls.SignatureAndHashAlgorithm{
					Hash:      tls.SHA256,
					Signature: tls.RSA,
				},
				Signature: signature,
			},
		}
		scts = append(scts, &sct)
	}
	sctList, err := ctx509util.MarshalSCTsIntoSCTList(scts)
	if err != nil {
		t.Fatal(err)
	}
	sctBytes, err := tls.Marshal(*sctList)
	if err != nil {
		t.Fatal(err)
	}
	asnSCT, err := asn1.Marshal(sctBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: preCert.SerialNumber,
		SubjectKeyId: skid,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT),
				Value: asnSCT,
			},
		},
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCert
}

type fakeTrustedMaterial struct {
	transparencyLog map[string]*root.TransparencyLog
	cas             []root.CertificateAuthority
}

func (t *fakeTrustedMaterial) CTLogs() map[string]*root.TransparencyLog {
	return t.transparencyLog
}

func (t *fakeTrustedMaterial) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return t.cas
}

func (t *fakeTrustedMaterial) TimestampingAuthorities() []root.CertificateAuthority {
	panic("not implemented")
}
func (t *fakeTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog { panic("not implemented") }
func (t *fakeTrustedMaterial) PublicKeyVerifier(string) (root.TimeConstrainedVerifier, error) {
	panic("not implemented")
}
