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

package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// oidExtensionCTSCT is the X.509 extension OID for embedded SCT lists (RFC 6962 Section 3.3).
	oidExtensionCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

const (
	// RFC 6962 Section 3.1 & 3.2 constants.
	sctVersionV1                      uint8  = 0
	signatureTypeCertificateTimestamp uint8  = 0
	logEntryTypePrecert               uint16 = 1

	// RFC 5246 Section 7.4.1.4.1 HashAlgorithm values.
	tlsHashSHA256 uint8 = 4
	tlsHashSHA384 uint8 = 5
	tlsHashSHA512 uint8 = 6

	// RFC 5246 Section 7.4.1.4.1 SignatureAlgorithm values.
	tlsSigRSA   uint8 = 1
	tlsSigECDSA uint8 = 3
)

// signedCertificateTimestamp represents a parsed RFC 6962 Section 3.2 SCT.
type signedCertificateTimestamp struct {
	version       uint8
	logID         [sha256.Size]byte
	timestamp     uint64
	extensions    []byte
	hashAlgorithm uint8
	sigAlgorithm  uint8
	signature     []byte
}

// VerifySignedCertificateTimestamp, given verified certificate chains, a
// threshold, and TrustedMaterial, will extract the embedded SCTs from the leaf
// certificate (the first certificate of the first chain) and verify them
// using the TrustedMaterial's CTLogs(). The issuer key hash covered by each
// SCT is taken from the leaf's direct issuer, the second certificate of each
// chain. Verification succeeds if SCTs from at least threshold distinct logs
// verify.
//
// Only RFC 6962 v1 SCTs signed with SHA-256, SHA-384, or SHA-512 and RSA
// PKCS#1 v1.5 or ECDSA are accepted, and CT log keys must be RSA of at least
// 2048 bits or ECDSA P-256.
func VerifySignedCertificateTimestamp(chains [][]*x509.Certificate, threshold int, trustedMaterial root.TrustedMaterial) error { // nolint: revive
	if len(chains) == 0 || len(chains[0]) == 0 || chains[0][0] == nil {
		return errors.New("no chains provided")
	}
	// The first certificate in the chain is always the leaf certificate
	leaf := chains[0][0]

	ctlogs := trustedMaterial.CTLogs()

	scts, err := parseSCTsFromCertificate(leaf)
	if err != nil {
		return err
	}

	var tbsCert []byte
	if len(scts) > 0 {
		tbsCert, err = removeSCTListExtension(leaf.RawTBSCertificate)
		if err != nil {
			return err
		}
	}

	verifiedLogs := make(map[string]bool)
	for _, sct := range scts {
		encodedKeyID := hex.EncodeToString(sct.logID[:])
		if verifiedLogs[encodedKeyID] {
			// Skip verification of SCTs from the same log after one successful verification.
			continue
		}
		key, ok := ctlogs[encodedKeyID]
		if !ok {
			// Skip entries the trust root cannot verify
			continue
		}

		// Ensure sct is within ctlog validity window
		sctTime := timestampToTime(sct.timestamp)
		if !key.ValidityPeriodStart.IsZero() && sctTime.Before(key.ValidityPeriodStart) {
			// skip entries that were before ctlog key start time
			continue
		}
		if !key.ValidityPeriodEnd.IsZero() && sctTime.After(key.ValidityPeriodEnd) {
			// skip entries that were after ctlog key end time
			continue
		}

		for _, chain := range chains {
			if len(chain) < 2 || chain[1] == nil {
				continue
			}

			issuerKeyHash := sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
			if err := verifySCTSignature(key.PublicKey, sct, issuerKeyHash, tbsCert); err == nil {
				verifiedLogs[encodedKeyID] = true
				break
			}
		}
	}

	if len(verifiedLogs) < threshold {
		return fmt.Errorf("only able to verify %d SCT entries; unable to meet threshold of %d", len(verifiedLogs), threshold)
	}

	return nil
}

// timestampToTime converts an RFC 6962 timestamp (milliseconds since UNIX epoch) to time.Time.
func timestampToTime(ts uint64) time.Time {
	secs := int64(ts / 1000) //nolint:gosec // max uint64/1000 < math.MaxInt64
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*int64(time.Millisecond))
}

// parseSCTsFromCertificate extracts and parses any embedded SCTs from the certificate's
// RFC 6962 SCT list extension. If the extension is absent, it returns nil, nil.
func parseSCTsFromCertificate(cert *x509.Certificate) ([]*signedCertificateTimestamp, error) {
	var sctExtValue []byte
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionCTSCT) {
			if found {
				return nil, errors.New("multiple SCT list extensions present")
			}
			sctExtValue = ext.Value
			found = true
		}
	}
	if !found {
		return nil, nil
	}

	var rawSCTList []byte
	rest, err := asn1.Unmarshal(sctExtValue, &rawSCTList)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SCT list extension: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing data after ASN.1-encoded SCT list")
	}

	s := cryptobyte.String(rawSCTList)
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || list.Empty() || !s.Empty() {
		return nil, errors.New("invalid TLS-encoded SCT list")
	}

	var scts []*signedCertificateTimestamp
	for !list.Empty() {
		var serializedSCT cryptobyte.String
		if !list.ReadUint16LengthPrefixed(&serializedSCT) || serializedSCT.Empty() {
			return nil, errors.New("invalid serialized SCT in SCT list")
		}
		sct, err := parseSCT(serializedSCT)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SCT: %w", err)
		}
		scts = append(scts, sct)
	}
	return scts, nil
}

// parseSCT parses a single TLS-encoded RFC 6962 SignedCertificateTimestamp.
func parseSCT(s cryptobyte.String) (*signedCertificateTimestamp, error) {
	var sct signedCertificateTimestamp
	if !s.ReadUint8(&sct.version) {
		return nil, errors.New("failed to read SCT version")
	}
	var logID []byte
	if !s.ReadBytes(&logID, sha256.Size) {
		return nil, errors.New("failed to read SCT log ID")
	}
	copy(sct.logID[:], logID)
	if !s.ReadUint64(&sct.timestamp) {
		return nil, errors.New("failed to read SCT timestamp")
	}
	if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&sct.extensions)) {
		return nil, errors.New("failed to read SCT extensions")
	}
	if !s.ReadUint8(&sct.hashAlgorithm) || !s.ReadUint8(&sct.sigAlgorithm) {
		return nil, errors.New("failed to read SCT signature algorithm")
	}
	if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&sct.signature)) {
		return nil, errors.New("failed to read SCT signature")
	}
	if !s.Empty() {
		return nil, fmt.Errorf("trailing data (%d bytes) after serialized SCT", len(s))
	}
	return &sct, nil
}

// removeSCTListExtension removes the RFC 6962 SCT list extension from a DER-encoded
// TBSCertificate while preserving all other fields and extensions verbatim.
func removeSCTListExtension(rawTBSCertificate []byte) ([]byte, error) {
	input := cryptobyte.String(rawTBSCertificate)
	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("invalid DER-encoded TBSCertificate")
	}

	extensionsTag := cryptobyte_asn1.Tag(3).ContextSpecific().Constructed()

	var b cryptobyte.Builder
	var foundSCTExt bool
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for !tbs.Empty() {
			var elem cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !tbs.ReadAnyASN1Element(&elem, &tag) {
				b.SetError(errors.New("failed to read TBSCertificate element"))
				return
			}
			if tag != extensionsTag {
				b.AddBytes(elem)
				continue
			}

			var extExplicit, extSeq cryptobyte.String
			if !elem.ReadASN1(&extExplicit, extensionsTag) || !elem.Empty() {
				b.SetError(errors.New("failed to read extensions tag"))
				return
			}
			if !extExplicit.ReadASN1(&extSeq, cryptobyte_asn1.SEQUENCE) || !extExplicit.Empty() {
				b.SetError(errors.New("failed to read extensions sequence"))
				return
			}

			var keptExtensions [][]byte
			for !extSeq.Empty() {
				var extElem, extBody cryptobyte.String
				if !extSeq.ReadASN1Element(&extElem, cryptobyte_asn1.SEQUENCE) {
					b.SetError(errors.New("failed to read extension element"))
					return
				}
				extCopy := extElem
				if !extCopy.ReadASN1(&extBody, cryptobyte_asn1.SEQUENCE) {
					b.SetError(errors.New("failed to read extension body"))
					return
				}
				var oid asn1.ObjectIdentifier
				if !extBody.ReadASN1ObjectIdentifier(&oid) {
					b.SetError(errors.New("failed to read extension OID"))
					return
				}
				if oid.Equal(oidExtensionCTSCT) {
					if foundSCTExt {
						b.SetError(errors.New("multiple SCT list extensions present"))
						return
					}
					foundSCTExt = true
					continue
				}
				keptExtensions = append(keptExtensions, extElem)
			}

			// RFC 5280: Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
			// Omit the optional [3] EXPLICIT extensions field if no extensions remain.
			if len(keptExtensions) > 0 {
				b.AddASN1(extensionsTag, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						for _, ext := range keptExtensions {
							b.AddBytes(ext)
						}
					})
				})
			}
		}
	})

	out, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if !foundSCTExt {
		return nil, errors.New("no SCT list extension present")
	}
	return out, nil
}

// serializePrecertSCTSignatureInput builds the TLS-encoded CertificateTimestamp
// structure that an embedded SCT signature covers (RFC 6962 Section 3.2).
func serializePrecertSCTSignatureInput(sct *signedCertificateTimestamp, issuerKeyHash [sha256.Size]byte, tbsCert []byte) ([]byte, error) {
	if sct.version != sctVersionV1 {
		return nil, fmt.Errorf("unknown SCT version %d", sct.version)
	}
	if len(tbsCert) == 0 {
		return nil, errors.New("empty TBSCertificate")
	}

	var b cryptobyte.Builder
	b.AddUint8(sct.version)
	b.AddUint8(signatureTypeCertificateTimestamp)
	b.AddUint64(sct.timestamp)
	b.AddUint16(logEntryTypePrecert)
	b.AddBytes(issuerKeyHash[:])
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(tbsCert)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sct.extensions)
	})
	return b.Bytes()
}

// verifySCTSignature verifies the cryptographic signature on an embedded precertificate SCT.
// tbsCert must be the leaf's TBSCertificate with the SCT list extension removed.
func verifySCTSignature(pubKey crypto.PublicKey, sct *signedCertificateTimestamp, issuerKeyHash [sha256.Size]byte, tbsCert []byte) error {
	// Validate CT log public key compliance per RFC 6962 Section 2.1.4.
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA public key has < 2048 bits (%d)", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return errors.New("ECDSA public key is not on P-256 curve")
		}
	default:
		return fmt.Errorf("unsupported CT log public key type %T", pubKey)
	}

	data, err := serializePrecertSCTSignatureInput(sct, issuerKeyHash, tbsCert)
	if err != nil {
		return err
	}

	var hashType crypto.Hash
	var digest []byte
	switch sct.hashAlgorithm {
	case tlsHashSHA256:
		hashType = crypto.SHA256
		sum := sha256.Sum256(data)
		digest = sum[:]
	case tlsHashSHA384:
		hashType = crypto.SHA384
		sum := sha512.Sum384(data)
		digest = sum[:]
	case tlsHashSHA512:
		hashType = crypto.SHA512
		sum := sha512.Sum512(data)
		digest = sum[:]
	default:
		return fmt.Errorf("unsupported hash algorithm %d", sct.hashAlgorithm)
	}

	switch sct.sigAlgorithm {
	case tlsSigRSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("cannot verify RSA signature with %T key", pubKey)
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, hashType, digest, sct.signature); err != nil {
			return fmt.Errorf("failed to verify RSA signature: %w", err)
		}
	case tlsSigECDSA:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("cannot verify ECDSA signature with %T key", pubKey)
		}
		if !ecdsa.VerifyASN1(ecdsaKey, digest, sct.signature) {
			return errors.New("failed to verify ECDSA signature")
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %d", sct.sigAlgorithm)
	}

	return nil
}
