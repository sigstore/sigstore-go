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

package root

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	FulcioTarget = "Fulcio"
	RekorTarget  = "Rekor"
	CTFETarget   = "CTFE"
	TSATarget    = "TSA"
)

type RawTrustedRootTarget interface {
	GetType() string
	GetBytes() []byte
}

type BaseTrustedRootTarget struct {
	Type  string
	Bytes []byte
}

func (b *BaseTrustedRootTarget) GetType() string {
	return b.Type
}

func (b *BaseTrustedRootTarget) GetBytes() []byte {
	return b.Bytes
}

// NewTrustedRootFromTargets initializes a TrustedRoot object from a mediaType string and
// a slice of targets. These targets are expected to be PEM-encoded public keys/certificate chains.
// This method of constructing the TrustedRoot has some shortcomings which can be aided by manually
// adjusting the TrustedRoot object after instantiation:
//
//   - publicKey instances for tlogs/ctlogs will have validFor.start set to Time.now() and no validFor.end.
//   - Merkle Tree hash function is hardcoded to SHA256, as this is not derivable from the public key.
//   - Each certificate chain is expected to be given as a single target, where there is a newline
//     between individual certificates. It is expected that the certificate chain is ordered (root last).
func NewTrustedRootFromTargets(mediaType string, targets []RawTrustedRootTarget) (*TrustedRoot, error) {
	// document that we assume 1 cert chain per target and with certs already ordered from leaf to root
	if mediaType != TrustedRootMediaType01 {
		return nil, fmt.Errorf("unsupported TrustedRoot media type: %s", TrustedRootMediaType01)
	}
	tr := &TrustedRoot{
		ctLogs:    make(map[string]*TransparencyLog),
		rekorLogs: make(map[string]*TransparencyLog),
	}
	now := time.Now()

	var fulcioCertChains, tsaCertChains [][]byte

	for _, target := range targets {
		switch target.GetType() {
		case FulcioTarget:
			fulcioCertChains = append(fulcioCertChains, target.GetBytes())
		case TSATarget:
			tsaCertChains = append(tsaCertChains, target.GetBytes())
		case RekorTarget:
			tlInstance, keyID, err := pubkeyToTransparencyLogInstance(target.GetBytes(), now)
			if err != nil {
				return nil, fmt.Errorf("failed to parse rekor key: %w", err)
			}
			tr.rekorLogs[keyID] = tlInstance
		case CTFETarget:
			tlInstance, keyID, err := pubkeyToTransparencyLogInstance(target.GetBytes(), now)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ctlog key: %w", err)
			}
			tr.ctLogs[keyID] = tlInstance
		}
	}

	for _, fulcioCertChain := range fulcioCertChains {
		fulcioCA, err := certsToAuthority(fulcioCertChain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Fulcio certificate chain: %w", err)
		}
		tr.fulcioCertAuthorities = append(tr.fulcioCertAuthorities, *fulcioCA)
	}

	for _, tsaCertChain := range tsaCertChains {
		tsaCA, err := certsToAuthority(tsaCertChain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TSA certificate chain: %w", err)
		}
		tr.timestampingAuthorities = append(tr.timestampingAuthorities, *tsaCA)
	}

	return tr, nil
}

func pubkeyToTransparencyLogInstance(keyBytes []byte, tm time.Time) (*TransparencyLog, string, error) {
	logID := sha256.Sum256(keyBytes)
	der, _ := pem.Decode(keyBytes)
	if der == nil {
		return nil, "", errors.New("failed to read PEM data for key")
	}
	key, keyDetails, err := getKeyWithDetails(der.Bytes)
	if err != nil {
		return nil, "", err
	}

	return &TransparencyLog{
		BaseURL:             "",
		ID:                  logID[:],
		ValidityPeriodStart: tm,
		HashFunc:            crypto.SHA256, // we can't get this from the keyBytes, assume SHA256
		PublicKey:           key,
		SignatureHashFunc:   keyDetails,
	}, hex.EncodeToString(logID[:]), nil
}

func getKeyWithDetails(key []byte) (crypto.PublicKey, crypto.Hash, error) {
	var k any
	var hashFunc crypto.Hash
	var err1, err2 error

	k, err1 = x509.ParsePKCS1PublicKey(key)
	if err1 != nil {
		k, err2 = x509.ParsePKIXPublicKey(key)
		if err2 != nil {
			return 0, 0, fmt.Errorf("can't parse public key with PKCS1 or PKIX: %w, %w", err1, err2)
		}
	}

	switch v := k.(type) {
	case *ecdsa.PublicKey:
		switch v.Curve {
		case elliptic.P256():
			hashFunc = crypto.SHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
		case elliptic.P521():
			hashFunc = crypto.SHA512
		default:
			return 0, 0, fmt.Errorf("unsupported elliptic curve %T", v.Curve)
		}
	case *rsa.PublicKey:
		switch v.Size() * 8 {
		case 2048, 3072, 4096:
			hashFunc = crypto.SHA256
		default:
			return 0, 0, fmt.Errorf("unsupported public modulus %d", v.Size())
		}
	default:
		return 0, 0, errors.New("unknown public key type")
	}

	return k, hashFunc, nil
}

func certsToAuthority(certChainPem []byte) (*CertificateAuthority, error) {
	var cert *x509.Certificate
	var err error
	rest := certChainPem
	certChain := []*x509.Certificate{}

	// skip potential whitespace at end of file (8 is kinda random, but seems to work fine)
	for len(rest) > 8 {
		var derCert *pem.Block
		derCert, rest = pem.Decode(rest)
		if derCert == nil {
			return nil, fmt.Errorf("input is left, but it is not a certificate: %+v", rest)
		}
		cert, err = x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certChain = append(certChain, cert)
	}
	if len(certChain) == 0 {
		return nil, fmt.Errorf("no certificates found in input")
	}

	ca := CertificateAuthority{}

	for i, cert := range certChain {
		switch {
		case i == 0 && !cert.IsCA:
			ca.Leaf = cert
		case i < len(certChain)-1:
			ca.Intermediates = append(ca.Intermediates, cert)
		case i == len(certChain)-1:
			ca.Root = cert
		}
	}

	ca.ValidityPeriodStart = certChain[0].NotBefore
	ca.ValidityPeriodEnd = certChain[0].NotAfter

	return &ca, nil
}

func (tr *TrustedRoot) constructProtoTrustRoot() error {
	tr.trustedRoot = &prototrustroot.TrustedRoot{}
	tr.trustedRoot.MediaType = TrustedRootMediaType01

	for logID, transparencyLog := range tr.rekorLogs {
		tlProto, err := transparencyLogToProtobufTL(*transparencyLog)
		if err != nil {
			return fmt.Errorf("failed converting rekor log %s to protobuf: %w", logID, err)
		}
		tr.trustedRoot.Tlogs = append(tr.trustedRoot.Tlogs, tlProto)
		// ensure stable sorting of the slice
		sort.Slice(tr.trustedRoot.Tlogs, func(i, j int) bool {
			iTime := time.Unix(0, 0)
			jTime := time.Unix(0, 0)

			if tr.trustedRoot.Tlogs[i].PublicKey.ValidFor.Start != nil {
				iTime = tr.trustedRoot.Tlogs[i].PublicKey.ValidFor.Start.AsTime()
			}
			if tr.trustedRoot.Tlogs[j].PublicKey.ValidFor.Start != nil {
				iTime = tr.trustedRoot.Tlogs[j].PublicKey.ValidFor.Start.AsTime()
			}
			return iTime.Before(jTime)
		})
	}

	for logID, ctLog := range tr.ctLogs {
		ctProto, err := transparencyLogToProtobufTL(*ctLog)
		if err != nil {
			return fmt.Errorf("failed converting ctlog %s to protobuf: %w", logID, err)
		}
		tr.trustedRoot.Ctlogs = append(tr.trustedRoot.Ctlogs, ctProto)
		// ensure stable sorting of the slice
		sort.Slice(tr.trustedRoot.Ctlogs, func(i, j int) bool {
			iTime := time.Unix(0, 0)
			jTime := time.Unix(0, 0)

			if tr.trustedRoot.Ctlogs[i].PublicKey.ValidFor.Start != nil {
				iTime = tr.trustedRoot.Ctlogs[i].PublicKey.ValidFor.Start.AsTime()
			}
			if tr.trustedRoot.Ctlogs[j].PublicKey.ValidFor.Start != nil {
				iTime = tr.trustedRoot.Ctlogs[j].PublicKey.ValidFor.Start.AsTime()
			}
			return iTime.Before(jTime)
		})
	}

	for _, ca := range tr.fulcioCertAuthorities {
		caProto, err := certificateAuthorityToProtobufCA(ca)
		if err != nil {
			return fmt.Errorf("failed converting fulcio cert chain to protobuf: %w", err)
		}
		tr.trustedRoot.CertificateAuthorities = append(tr.trustedRoot.CertificateAuthorities, caProto)
	}

	for _, ca := range tr.timestampingAuthorities {
		caProto, err := certificateAuthorityToProtobufCA(ca)
		if err != nil {
			return fmt.Errorf("failed converting TSA cert chain to protobuf: %w", err)
		}
		tr.trustedRoot.TimestampAuthorities = append(tr.trustedRoot.TimestampAuthorities, caProto)
	}

	return nil
}

func certificateAuthorityToProtobufCA(ca CertificateAuthority) (*prototrustroot.CertificateAuthority, error) {
	org := ""
	if len(ca.Root.Subject.Organization) > 0 {
		org = ca.Root.Subject.Organization[0]
	}
	var allCerts []*protocommon.X509Certificate
	if ca.Leaf != nil {
		allCerts = append(allCerts, &protocommon.X509Certificate{RawBytes: ca.Leaf.Raw})
	}
	for _, intermed := range ca.Intermediates {
		allCerts = append(allCerts, &protocommon.X509Certificate{RawBytes: intermed.Raw})
	}
	if ca.Root == nil {
		return nil, fmt.Errorf("root certificate is nil")
	}
	allCerts = append(allCerts, &protocommon.X509Certificate{RawBytes: ca.Root.Raw})

	caProto := prototrustroot.CertificateAuthority{
		Uri: ca.URI,
		Subject: &protocommon.DistinguishedName{
			Organization: org,
			CommonName:   ca.Root.Subject.CommonName,
		},
		ValidFor: &protocommon.TimeRange{
			Start: timestamppb.New(ca.ValidityPeriodStart),
		},
		CertChain: &protocommon.X509CertificateChain{
			Certificates: allCerts,
		},
	}

	if !ca.ValidityPeriodEnd.IsZero() {
		caProto.ValidFor.End = timestamppb.New(ca.ValidityPeriodEnd)
	}

	return &caProto, nil
}

func transparencyLogToProtobufTL(tl TransparencyLog) (*prototrustroot.TransparencyLogInstance, error) {
	hashAlgo, err := hashAlgorithmToProtobufHashAlgorithm(tl.HashFunc)
	if err != nil {
		return nil, fmt.Errorf("failed converting hash algorithm to protobuf: %w", err)
	}
	publicKey, err := publicKeyToProtobufPublicKey(tl.PublicKey, tl.ValidityPeriodStart, tl.ValidityPeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("failed converting public key to protobuf: %w", err)
	}
	trProto := prototrustroot.TransparencyLogInstance{
		BaseUrl:       tl.BaseURL,
		HashAlgorithm: hashAlgo,
		PublicKey:     publicKey,
		LogId: &protocommon.LogId{
			KeyId: tl.ID,
		},
	}

	return &trProto, nil
}

func hashAlgorithmToProtobufHashAlgorithm(hashAlgorithm crypto.Hash) (protocommon.HashAlgorithm, error) {
	switch hashAlgorithm {
	case crypto.SHA256:
		return protocommon.HashAlgorithm_SHA2_256, nil
	case crypto.SHA384:
		return protocommon.HashAlgorithm_SHA2_384, nil
	case crypto.SHA512:
		return protocommon.HashAlgorithm_SHA2_512, nil
	case crypto.SHA3_256:
		return protocommon.HashAlgorithm_SHA3_256, nil
	case crypto.SHA3_384:
		return protocommon.HashAlgorithm_SHA3_384, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm for Merkle tree: %v", hashAlgorithm)
	}
}

func publicKeyToProtobufPublicKey(publicKey crypto.PublicKey, start time.Time, end time.Time) (*protocommon.PublicKey, error) {
	pkd := protocommon.PublicKey{
		ValidFor: &protocommon.TimeRange{
			Start: timestamppb.New(start),
		},
	}

	if !end.IsZero() {
		pkd.ValidFor.End = timestamppb.New(end)
	}

	rawBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling public key: %w", err)
	}
	pkd.RawBytes = rawBytes

	switch p := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case elliptic.P384():
			pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		case elliptic.P521():
			pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
		default:
			return nil, fmt.Errorf("unsupported curve for ecdsa key: %T", p.Curve)
		}
	case *rsa.PublicKey:
		switch p.Size() * 8 {
		case 2048:
			pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
		case 3072:
			pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256
		case 4096:
			pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256
		default:
			return nil, fmt.Errorf("unsupported public modulus for RSA key: %d", p.Size())
		}
	case *ed25519.PublicKey:
		pkd.KeyDetails = protocommon.PublicKeyDetails_PKIX_ED25519
	default:
		return nil, fmt.Errorf("unknown public key type: %T", p)
	}

	return &pkd, nil
}
