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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func getCTLogID(pub any) ([32]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(der), nil
}

func TestVerifySignedCertificateTimestamp(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	anotherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaP384PrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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
	logID, err := getCTLogID(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	anotherLogID, err := getCTLogID(&anotherPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaLogID, err := getCTLogID(&ecdsaPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaP384LogID, err := getCTLogID(&ecdsaP384PrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name            string
		getCertFn       func() *x509.Certificate
		chain           []*x509.Certificate // only intermediate and root
		threshold       int
		trustedMaterial root.TrustedMaterial
		wantErr         bool
	}{
		{
			name:            "missing sct in cert",
			getCertFn:       func() *x509.Certificate { return createBaseCert(t, privateKey, skid, big.NewInt(1)) },
			chain:           []*x509.Certificate{},
			threshold:       1,
			trustedMaterial: &fakeTrustedMaterial{},
			wantErr:         true,
		},
		{
			name: "sct missing from ct logs",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     logID,
				}})
			},
			chain:     []*x509.Certificate{},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{},
			},
			wantErr: true,
		},
		{
			name: "missing fulcio CAs",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     logID,
				}})
			},
			chain:     []*x509.Certificate{},
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
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     logID,
				}})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey:           &privateKey.PublicKey,
						ValidityPeriodStart: time.UnixMilli(12344),
						ValidityPeriodEnd:   time.UnixMilli(12346),
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "one valid ecdsa p256 sct",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, []crypto.Signer{ecdsaPrivateKey}, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     ecdsaLogID,
				}})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(ecdsaLogID[:]): {
						PublicKey: &ecdsaPrivateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "non-compliant ecdsa p384 ct log key rejected",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, []crypto.Signer{ecdsaP384PrivateKey}, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     ecdsaP384LogID,
				}})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(ecdsaP384LogID[:]): {
						PublicKey: &ecdsaP384PrivateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "sct as only extension in cert",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, nil, createBaseCert(t, privateKey, nil, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     logID,
				}})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "one invalid sct",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     [32]byte{1, 2, 3, 4},
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "one valid sct out of multiple invalid scts",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     logID,
					},
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     [32]byte{1, 2, 3, 4},
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "threshold of 2 with only 1 valid sct",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     logID,
					},
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     [32]byte{1, 2, 3, 4},
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 2,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no valid scts out of multiple",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     [32]byte{0, 1, 2, 3},
					},
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     [32]byte{4, 5, 6, 7},
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "fulcio CA has intermediates",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     logID,
				}})
			},
			chain:     []*x509.Certificate{caCert, caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
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
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   sctVersionV1,
					timestamp: 12345,
					logID:     logID,
				}})
			},
			chain:     []*x509.Certificate{anotherCACert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: anotherCACert,
					},
				},
			},
			wantErr: true,
		},
		{
			name:            "threshold of 0",
			getCertFn:       func() *x509.Certificate { return createBaseCert(t, privateKey, skid, big.NewInt(1)) },
			chain:           []*x509.Certificate{},
			threshold:       0,
			trustedMaterial: &fakeTrustedMaterial{},
		},
		{
			name: "sct not valid for ctlog key time range",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     logID,
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey:           &privateKey.PublicKey,
						ValidityPeriodStart: time.UnixMilli(10),
						ValidityPeriodEnd:   time.UnixMilli(10000),
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "threshold of 2 with 2 valid scts from same log (fails)",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, nil, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     logID,
					},
					{
						version:   sctVersionV1,
						timestamp: 99,
						logID:     logID,
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 2,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "threshold of 2 with 2 valid scts from different logs (succeeds)",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, []crypto.Signer{privateKey, anotherPrivateKey}, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{
					{
						version:   sctVersionV1,
						timestamp: 12345,
						logID:     logID,
					},
					{
						version:   sctVersionV1,
						timestamp: 99,
						logID:     anotherLogID,
					},
				})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 2,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
					hex.EncodeToString(anotherLogID[:]): {
						PublicKey: &anotherPrivateKey.PublicKey,
					},
				},
				cas: []root.CertificateAuthority{
					&root.FulcioCertificateAuthority{
						Root: caCert,
					},
				},
			},
		},
		{
			name: "one valid sct with sct extensions",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, []crypto.Signer{ecdsaPrivateKey}, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:    sctVersionV1,
					timestamp:  12345,
					logID:      ecdsaLogID,
					extensions: []byte{1, 2, 3},
				}})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(ecdsaLogID[:]): {
						PublicKey: &ecdsaPrivateKey.PublicKey,
					},
				},
			},
		},
		{
			name: "unsupported sct version",
			getCertFn: func() *x509.Certificate {
				return embedSCTs(t, privateKey, []crypto.Signer{ecdsaPrivateKey}, skid, createBaseCert(t, privateKey, skid, big.NewInt(1)), []signedCertificateTimestamp{{
					version:   1,
					timestamp: 12345,
					logID:     ecdsaLogID,
				}})
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(ecdsaLogID[:]): {
						PublicKey: &ecdsaPrivateKey.PublicKey,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "malformed sct extension",
			getCertFn: func() *x509.Certificate {
				asnSCT, err := asn1.Marshal([]byte{0x00, 0x05, 0x01})
				if err != nil {
					t.Fatal(err)
				}
				cert := &x509.Certificate{
					SerialNumber: big.NewInt(1),
					SubjectKeyId: skid,
					ExtraExtensions: []pkix.Extension{
						{
							Id:    oidExtensionCTSCT,
							Value: asnSCT,
						},
					},
				}
				certDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := x509.ParseCertificate(certDER)
				if err != nil {
					t.Fatal(err)
				}
				return parsed
			},
			chain:     []*x509.Certificate{caCert},
			threshold: 1,
			trustedMaterial: &fakeTrustedMaterial{
				transparencyLog: map[string]*root.TransparencyLog{
					hex.EncodeToString(logID[:]): {
						PublicKey: &privateKey.PublicKey,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := []*x509.Certificate{test.getCertFn()}
			chain = append(chain, test.chain...)
			err = VerifySignedCertificateTimestamp([][]*x509.Certificate{chain}, test.threshold, test.trustedMaterial)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func createBaseCert(t testing.TB, privateKey *rsa.PrivateKey, skid []byte, serialNumber *big.Int) *x509.Certificate {
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

func (t *fakeTrustedMaterial) TimestampingAuthorities() []root.TimestampingAuthority {
	panic("not implemented")
}
func (t *fakeTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog { panic("not implemented") }
func (t *fakeTrustedMaterial) PublicKeyVerifier(string) (root.TimeConstrainedVerifier, error) {
	panic("not implemented")
}
func (t *fakeTrustedMaterial) PublicKeyVerifiers() []root.TimeConstrainedVerifier {
	panic("not implemented")
}

// precertSignatureInput builds the RFC 6962 Section 3.2 digitally-signed
// structure for a precert_entry SCT. It is deliberately implemented
// separately from serializePrecertSCTSignatureInput so that the tests do not
// sign and verify with the same encoder.
func precertSignatureInput(t testing.TB, sct *signedCertificateTimestamp, issuerKeyHash [sha256.Size]byte, tbsCert []byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(sct.version)
	b.AddUint8(0) // SignatureType certificate_timestamp
	b.AddUint64(sct.timestamp)
	b.AddUint16(1) // LogEntryType precert_entry
	b.AddBytes(issuerKeyHash[:])
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tbsCert) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sct.extensions) })
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// signSCT returns a copy of sct signed by key using hash, with the hash and
// signature algorithm identifiers set to match.
func signSCT(t testing.TB, key crypto.Signer, hash crypto.Hash, sct signedCertificateTimestamp, issuerKeyHash [sha256.Size]byte, tbsCert []byte) *signedCertificateTimestamp {
	t.Helper()
	switch hash {
	case crypto.SHA256:
		sct.hashAlgorithm = tlsHashSHA256
	case crypto.SHA384:
		sct.hashAlgorithm = tlsHashSHA384
	case crypto.SHA512:
		sct.hashAlgorithm = tlsHashSHA512
	default:
		t.Fatalf("unsupported hash: %v", hash)
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		sct.sigAlgorithm = tlsSigRSA
	case *ecdsa.PublicKey:
		sct.sigAlgorithm = tlsSigECDSA
	default:
		t.Fatalf("unsupported key type: %T", key.Public())
	}
	h := hash.New()
	h.Write(precertSignatureInput(t, &sct, issuerKeyHash, tbsCert))
	signature, err := key.Sign(rand.Reader, h.Sum(nil), hash)
	if err != nil {
		t.Fatal(err)
	}
	sct.signature = signature
	return &sct
}

// embedSCTs signs each SCT in sctInput over preCert and embeds them in a newly
// created certificate issued by issuerKey. sctKeys[i] signs sctInput[i]; if
// sctKeys is nil, issuerKey signs every SCT.
func embedSCTs(t testing.TB, issuerKey crypto.Signer, sctKeys []crypto.Signer, skid []byte, preCert *x509.Certificate, sctInput []signedCertificateTimestamp) *x509.Certificate {
	t.Helper()
	if sctKeys != nil && len(sctKeys) != len(sctInput) {
		t.Fatalf("got %d SCT keys for %d SCTs", len(sctKeys), len(sctInput))
	}
	issuerKeyHash := sha256.Sum256(preCert.RawSubjectPublicKeyInfo)
	var serialized [][]byte
	for i, s := range sctInput {
		key := issuerKey
		if sctKeys != nil {
			key = sctKeys[i]
		}
		signed := signSCT(t, key, crypto.SHA256, s, issuerKeyHash, preCert.RawTBSCertificate)
		serialized = append(serialized, marshalSCT(t, signed))
	}
	extValue := octetString(t, marshalSCTList(t, serialized...))
	return createCertWithSCTExtension(t, issuerKey, skid, preCert.SerialNumber, extValue)
}

func TestParseSCT(t *testing.T) {
	want := testSCT()
	valid := marshalSCT(t, want)

	got, err := parseSCT(valid)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	noExtensions := testSCT()
	noExtensions.extensions = nil
	got, err = parseSCT(marshalSCT(t, noExtensions))
	require.NoError(t, err)
	assert.Empty(t, got.extensions)
	assert.Equal(t, noExtensions.signature, got.signature)

	for i := range valid {
		_, err := parseSCT(valid[:i])
		assert.Errorf(t, err, "SCT truncated to %d bytes", i)
	}

	_, err = parseSCT(append(bytes.Clone(valid), 0x00))
	assert.ErrorContains(t, err, "trailing data")
}

func TestParseSCTsFromCertificate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sct := marshalSCT(t, testSCT())
	list := marshalSCTList(t, sct)

	tests := []struct {
		name     string
		extValue []byte
		wantSCTs int
		wantErr  string
	}{
		{
			name:     "one sct",
			extValue: octetString(t, list),
			wantSCTs: 1,
		},
		{
			name:     "two scts",
			extValue: octetString(t, marshalSCTList(t, sct, sct)),
			wantSCTs: 2,
		},
		{
			name:     "not an octet string",
			extValue: []byte{0x02, 0x01, 0x2a},
			wantErr:  "failed to unmarshal SCT list extension",
		},
		{
			name:     "trailing data after octet string",
			extValue: append(octetString(t, list), 0x00),
			wantErr:  "trailing data after ASN.1-encoded SCT list",
		},
		{
			name:     "empty octet string",
			extValue: octetString(t, []byte{}),
			wantErr:  "invalid TLS-encoded SCT list",
		},
		{
			name:     "empty sct list",
			extValue: octetString(t, []byte{0x00, 0x00}),
			wantErr:  "invalid TLS-encoded SCT list",
		},
		{
			name:     "sct list shorter than its length prefix",
			extValue: octetString(t, list[:len(list)-1]),
			wantErr:  "invalid TLS-encoded SCT list",
		},
		{
			name:     "trailing data after sct list",
			extValue: octetString(t, append(bytes.Clone(list), 0x00)),
			wantErr:  "invalid TLS-encoded SCT list",
		},
		{
			name:     "zero-length sct",
			extValue: octetString(t, marshalSCTList(t, []byte{})),
			wantErr:  "invalid serialized SCT in SCT list",
		},
		{
			name:     "sct shorter than its length prefix",
			extValue: octetString(t, []byte{0x00, 0x03, 0x00, 0x05, 0x00}),
			wantErr:  "invalid serialized SCT in SCT list",
		},
		{
			name:     "truncated sct",
			extValue: octetString(t, marshalSCTList(t, sct[:len(sct)-1])),
			wantErr:  "failed to parse SCT",
		},
		{
			name:     "trailing data inside sct",
			extValue: octetString(t, marshalSCTList(t, append(bytes.Clone(sct), 0x00))),
			wantErr:  "trailing data",
		},
		{
			name:     "valid sct followed by invalid sct",
			extValue: octetString(t, marshalSCTList(t, sct, sct[:10])),
			wantErr:  "failed to parse SCT",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert := createCertWithSCTExtension(t, privateKey, nil, big.NewInt(1), test.extValue)
			scts, err := parseSCTsFromCertificate(cert)
			if test.wantErr != "" {
				assert.ErrorContains(t, err, test.wantErr)
				assert.Nil(t, scts)
				// Parse failures must fail verification even when no SCTs are required.
				assert.Error(t, VerifySignedCertificateTimestamp([][]*x509.Certificate{{cert, cert}}, 0, &fakeTrustedMaterial{}))
				return
			}
			require.NoError(t, err)
			assert.Len(t, scts, test.wantSCTs)
		})
	}

	t.Run("no sct extension", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		scts, err := parseSCTsFromCertificate(createBaseCert(t, rsaKey, nil, big.NewInt(1)))
		assert.NoError(t, err)
		assert.Nil(t, scts)
	})
}

func TestRemoveSCTListExtension(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	skid, err := cryptoutils.SKID(&privateKey.PublicKey)
	require.NoError(t, err)
	extValue := octetString(t, marshalSCTList(t, marshalSCT(t, testSCT())))

	// The expected output is the TBSCertificate of a certificate generated by
	// crypto/x509 without the SCT list extension.
	t.Run("with other extensions", func(t *testing.T) {
		base := createBaseCert(t, privateKey, skid, big.NewInt(7))
		require.NotEmpty(t, base.Extensions)
		withSCTs := createCertWithSCTExtension(t, privateKey, skid, big.NewInt(7), extValue)
		got, err := removeSCTListExtension(withSCTs.RawTBSCertificate)
		require.NoError(t, err)
		assert.Equal(t, base.RawTBSCertificate, got)
	})

	t.Run("sct list is the only extension", func(t *testing.T) {
		base := createBaseCert(t, privateKey, nil, big.NewInt(7))
		require.Empty(t, base.Extensions)
		withSCTs := createCertWithSCTExtension(t, privateKey, nil, big.NewInt(7), extValue)
		require.Len(t, withSCTs.Extensions, 1)
		got, err := removeSCTListExtension(withSCTs.RawTBSCertificate)
		require.NoError(t, err)
		assert.Equal(t, base.RawTBSCertificate, got)
	})

	withSCTs := createCertWithSCTExtension(t, privateKey, skid, big.NewInt(7), extValue)
	errTests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{
			name:    "no sct list extension",
			input:   createBaseCert(t, privateKey, skid, big.NewInt(7)).RawTBSCertificate,
			wantErr: "no SCT list extension present",
		},
		{
			name:    "no extensions",
			input:   createBaseCert(t, privateKey, nil, big.NewInt(7)).RawTBSCertificate,
			wantErr: "no SCT list extension present",
		},
		{
			name:    "empty input",
			input:   nil,
			wantErr: "invalid DER-encoded TBSCertificate",
		},
		{
			name:    "not a sequence",
			input:   []byte{0x04, 0x01, 0x00},
			wantErr: "invalid DER-encoded TBSCertificate",
		},
		{
			name:    "trailing data",
			input:   append(bytes.Clone(withSCTs.RawTBSCertificate), 0x00),
			wantErr: "invalid DER-encoded TBSCertificate",
		},
		{
			name:    "truncated",
			input:   withSCTs.RawTBSCertificate[:len(withSCTs.RawTBSCertificate)-1],
			wantErr: "invalid DER-encoded TBSCertificate",
		},
		{
			name:    "malformed element",
			input:   []byte{0x30, 0x03, 0x02, 0x05, 0x00},
			wantErr: "failed to read TBSCertificate element",
		},
		{
			name:    "extensions field does not contain a sequence",
			input:   []byte{0x30, 0x05, 0xa3, 0x03, 0x02, 0x01, 0x00},
			wantErr: "failed to read extensions sequence",
		},
		{
			name:    "extension is not a sequence",
			input:   []byte{0x30, 0x07, 0xa3, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00},
			wantErr: "failed to read extension element",
		},
		{
			name:    "extension does not start with an oid",
			input:   []byte{0x30, 0x09, 0xa3, 0x07, 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00},
			wantErr: "failed to read extension OID",
		},
	}
	for _, test := range errTests {
		t.Run(test.name, func(t *testing.T) {
			got, err := removeSCTListExtension(test.input)
			assert.ErrorContains(t, err, test.wantErr)
			assert.Nil(t, got)
		})
	}
}

func TestVerifySCTSignature(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	weakRSAKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // exercising rejection of weak keys
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	issuerKeyHash := sha256.Sum256([]byte("issuer key"))
	otherIssuerKeyHash := sha256.Sum256([]byte("another issuer key"))
	tbs := []byte("to-be-signed certificate")
	unsigned := signedCertificateTimestamp{
		version:   sctVersionV1,
		logID:     [sha256.Size]byte{1, 2, 3, 4},
		timestamp: 12345,
	}

	tests := []struct {
		name   string
		signer crypto.Signer
		hash   crypto.Hash
		// input, if set, replaces the default unsigned SCT before signing.
		input *signedCertificateTimestamp
		// mutate, if set, modifies the signed SCT before verification.
		mutate func(sct *signedCertificateTimestamp)
		// verifyKey, if set, is used instead of the signer's public key.
		verifyKey crypto.PublicKey
		// verifyIssuerKeyHash and verifyTBS, if set, replace the signed values.
		verifyIssuerKeyHash *[sha256.Size]byte
		verifyTBS           []byte
		wantErr             string
	}{
		{name: "rsa sha256", signer: rsaKey, hash: crypto.SHA256},
		{name: "rsa sha384", signer: rsaKey, hash: crypto.SHA384},
		{name: "rsa sha512", signer: rsaKey, hash: crypto.SHA512},
		{name: "ecdsa sha256", signer: ecdsaKey, hash: crypto.SHA256},
		{name: "ecdsa sha384", signer: ecdsaKey, hash: crypto.SHA384},
		{name: "ecdsa sha512", signer: ecdsaKey, hash: crypto.SHA512},
		{
			name:   "sct extensions are covered by the signature",
			signer: ecdsaKey,
			hash:   crypto.SHA256,
			input: &signedCertificateTimestamp{
				version:    sctVersionV1,
				timestamp:  12345,
				extensions: []byte{1, 2, 3},
			},
		},
		{
			name:    "tampered sct extensions",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.extensions = []byte{1} },
			wantErr: "failed to verify ECDSA signature",
		},
		{
			name:    "tampered timestamp",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.timestamp++ },
			wantErr: "failed to verify ECDSA signature",
		},
		{
			name:      "tampered tbs certificate",
			signer:    rsaKey,
			hash:      crypto.SHA256,
			verifyTBS: []byte("another to-be-signed certificate"),
			wantErr:   "failed to verify RSA signature",
		},
		{
			name:                "different issuer key hash",
			signer:              rsaKey,
			hash:                crypto.SHA256,
			verifyIssuerKeyHash: &otherIssuerKeyHash,
			wantErr:             "failed to verify RSA signature",
		},
		{
			name:      "different log key",
			signer:    rsaKey,
			hash:      crypto.SHA256,
			verifyKey: &otherRSAKey.PublicKey,
			wantErr:   "failed to verify RSA signature",
		},
		{
			name:    "unsupported sct version",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			input:   &signedCertificateTimestamp{version: 1, timestamp: 12345},
			wantErr: "unknown SCT version 1",
		},
		{
			name:    "hash algorithm none",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.hashAlgorithm = 0 },
			wantErr: "unsupported hash algorithm 0",
		},
		{
			name:    "hash algorithm sha1",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.hashAlgorithm = 2 },
			wantErr: "unsupported hash algorithm 2",
		},
		{
			name:    "hash algorithm does not match signature",
			signer:  rsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.hashAlgorithm = tlsHashSHA384 },
			wantErr: "failed to verify RSA signature",
		},
		{
			name:    "signature algorithm anonymous",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.sigAlgorithm = 0 },
			wantErr: "unsupported signature algorithm 0",
		},
		{
			name:    "signature algorithm dsa",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.sigAlgorithm = 2 },
			wantErr: "unsupported signature algorithm 2",
		},
		{
			name:    "rsa signature algorithm with ecdsa key",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.sigAlgorithm = tlsSigRSA },
			wantErr: "cannot verify RSA signature with *ecdsa.PublicKey key",
		},
		{
			name:    "ecdsa signature algorithm with rsa key",
			signer:  rsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.sigAlgorithm = tlsSigECDSA },
			wantErr: "cannot verify ECDSA signature with *rsa.PublicKey key",
		},
		{
			name:    "rsa key smaller than 2048 bits",
			signer:  weakRSAKey,
			hash:    crypto.SHA256,
			wantErr: "RSA public key has < 2048 bits",
		},
		{
			name:    "ecdsa key not on p256",
			signer:  p384Key,
			hash:    crypto.SHA256,
			wantErr: "ECDSA public key is not on P-256 curve",
		},
		{
			name:      "unsupported key type",
			signer:    ecdsaKey,
			hash:      crypto.SHA256,
			verifyKey: ed25519Pub,
			wantErr:   "unsupported CT log public key type ed25519.PublicKey",
		},
		{
			name:    "trailing data after ecdsa signature",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.signature = append(sct.signature, 0x00) },
			wantErr: "failed to verify ECDSA signature",
		},
		{
			name:    "empty ecdsa signature",
			signer:  ecdsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.signature = nil },
			wantErr: "failed to verify ECDSA signature",
		},
		{
			name:    "empty rsa signature",
			signer:  rsaKey,
			hash:    crypto.SHA256,
			mutate:  func(sct *signedCertificateTimestamp) { sct.signature = nil },
			wantErr: "failed to verify RSA signature",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := unsigned
			if test.input != nil {
				input = *test.input
			}
			sct := signSCT(t, test.signer, test.hash, input, issuerKeyHash, tbs)
			if test.mutate != nil {
				test.mutate(sct)
			}
			key := test.signer.Public()
			if test.verifyKey != nil {
				key = test.verifyKey
			}
			verifyIssuerKeyHash := issuerKeyHash
			if test.verifyIssuerKeyHash != nil {
				verifyIssuerKeyHash = *test.verifyIssuerKeyHash
			}
			verifyTBS := tbs
			if test.verifyTBS != nil {
				verifyTBS = test.verifyTBS
			}
			err := verifySCTSignature(key, sct, verifyIssuerKeyHash, verifyTBS)
			if test.wantErr != "" {
				assert.ErrorContains(t, err, test.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}

	t.Run("empty tbs certificate", func(t *testing.T) {
		sct := signSCT(t, ecdsaKey, crypto.SHA256, unsigned, issuerKeyHash, nil)
		assert.ErrorContains(t, verifySCTSignature(ecdsaKey.Public(), sct, issuerKeyHash, nil), "empty TBSCertificate")
	})

	t.Run("nil key", func(t *testing.T) {
		sct := signSCT(t, ecdsaKey, crypto.SHA256, unsigned, issuerKeyHash, tbs)
		assert.ErrorContains(t, verifySCTSignature(nil, sct, issuerKeyHash, tbs), "unsupported CT log public key type")
	})
}

func TestTimestampToTime(t *testing.T) {
	assert.True(t, time.Unix(0, 0).Equal(timestampToTime(0)))
	assert.True(t, time.UnixMilli(1700000000123).Equal(timestampToTime(1700000000123)))
}
