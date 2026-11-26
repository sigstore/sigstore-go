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

package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// These fuzz targets live in package verify, rather than alongside the
// targets in fuzz_test.go, because they exercise unexported parsers.

// FuzzParseSCT checks that parseSCT does not panic and that any SCT it
// accepts re-encodes to exactly the bytes that were parsed.
func FuzzParseSCT(f *testing.F) {
	valid := marshalSCT(f, testSCT())
	f.Add(valid)
	f.Add(valid[:len(valid)-1])
	f.Add(append(bytes.Clone(valid), 0x00))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		sct, err := parseSCT(data)
		if err != nil {
			return
		}
		if got := marshalSCT(t, sct); !bytes.Equal(got, data) {
			t.Fatalf("parsed SCT re-encodes to %x, want %x", got, data)
		}
	})
}

// FuzzParseSCTsFromCertificate checks that parsing an SCT list extension with
// arbitrary contents does not panic, and that a certificate whose SCT list is
// accepted can also have that extension removed.
func FuzzParseSCTsFromCertificate(f *testing.F) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	sct := marshalSCT(f, testSCT())
	f.Add(octetString(f, marshalSCTList(f, sct)))
	f.Add(octetString(f, marshalSCTList(f, sct, sct)))
	f.Add(octetString(f, []byte{0x00, 0x00}))
	f.Add([]byte{0x02, 0x01, 0x2a})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, extValue []byte) {
		skipLargeSCTFuzzInput(t, len(extValue))
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			ExtraExtensions: []pkix.Extension{
				{
					Id:    oidExtensionCTSCT,
					Value: extValue,
				},
			},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
		if err != nil {
			t.Skip()
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Skip()
		}
		scts, err := parseSCTsFromCertificate(cert)
		if err != nil {
			return
		}
		if len(scts) == 0 {
			t.Fatal("SCT list extension parsed without error but yielded no SCTs")
		}
		if _, err := removeSCTListExtension(cert.RawTBSCertificate); err != nil {
			t.Fatalf("failed to remove SCT list extension from parsed certificate: %v", err)
		}
	})
}

// FuzzRemoveSCTListExtension checks that removeSCTListExtension does not
// panic on arbitrary input and that its output is shorter than its input and
// no longer contains an SCT list extension.
func FuzzRemoveSCTListExtension(f *testing.F) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	extValue := octetString(f, marshalSCTList(f, marshalSCT(f, testSCT())))
	f.Add(createCertWithSCTExtension(f, privateKey, nil, big.NewInt(1), extValue).RawTBSCertificate)
	f.Add(createCertWithSCTExtension(f, privateKey, []byte{1, 2, 3, 4}, big.NewInt(1), extValue).RawTBSCertificate)
	f.Add([]byte{0x30, 0x05, 0xa3, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		skipLargeSCTFuzzInput(t, len(data))
		out, err := removeSCTListExtension(data)
		if err != nil {
			if out != nil {
				t.Fatal("output returned alongside an error")
			}
			return
		}
		if len(out) >= len(data) {
			t.Fatalf("output (%d bytes) is not shorter than input (%d bytes)", len(out), len(data))
		}
		if _, err := removeSCTListExtension(out); err == nil {
			t.Fatal("output still contains an SCT list extension")
		}
	})
}

func skipLargeSCTFuzzInput(t *testing.T, inputSize int) {
	t.Helper()
	if inputSize > 64*1024 {
		t.Skip()
	}
}

// The helpers below are shared with sct_test.go. They are defined here so that
// this file does not depend on other test files when built for OSS-Fuzz.

// marshalSCT TLS-encodes a single SCT.
func marshalSCT(t testing.TB, sct *signedCertificateTimestamp) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint8(sct.version)
	b.AddBytes(sct.logID[:])
	b.AddUint64(sct.timestamp)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sct.extensions) })
	b.AddUint8(sct.hashAlgorithm)
	b.AddUint8(sct.sigAlgorithm)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sct.signature) })
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// marshalSCTList TLS-encodes a SignedCertificateTimestampList.
func marshalSCTList(t testing.TB, serializedSCTs ...[]byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, s := range serializedSCTs {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s) })
		}
	})
	out, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// octetString DER-encodes data as an ASN.1 OCTET STRING.
func octetString(t testing.TB, data []byte) []byte {
	t.Helper()
	out, err := asn1.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// createCertWithSCTExtension creates a self-signed certificate that is
// identical to createBaseCert's output apart from an SCT list extension
// carrying extValue verbatim.
func createCertWithSCTExtension(t testing.TB, issuerKey crypto.Signer, skid []byte, serialNumber *big.Int, extValue []byte) *x509.Certificate {
	t.Helper()
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		SubjectKeyId: skid,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidExtensionCTSCT,
				Value: extValue,
			},
		},
	}
	certDERBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		t.Fatal(err)
	}
	return parsedCert
}

func testSCT() *signedCertificateTimestamp {
	return &signedCertificateTimestamp{
		version:       sctVersionV1,
		logID:         [sha256.Size]byte{1, 2, 3, 4},
		timestamp:     0x0102030405060708,
		extensions:    []byte{0xaa, 0xbb},
		hashAlgorithm: tlsHashSHA256,
		sigAlgorithm:  tlsSigECDSA,
		signature:     []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
	}
}
