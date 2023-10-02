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
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const TrustedRootMediaType01 = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

type TrustedRoot struct {
	BaseTrustedMaterial
	trustedRoot           *prototrustroot.TrustedRoot
	tlogAuthorities       map[string]*TlogAuthority
	fulcioCertAuthorities []CertificateAuthority
	ctLogAuthorities      map[string]*TlogAuthority
	tsaCertAuthorities    []CertificateAuthority
}

type CertificateAuthority struct {
	Root                *x509.Certificate
	Intermediates       []*x509.Certificate
	Leaf                *x509.Certificate
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
}

type TlogAuthority struct {
	BaseURL             string
	ID                  []byte
	ValidityPeriodStart time.Time
	ValidityPeriodEnd   time.Time
	// This is the hash algorithm used by the Merkle tree
	HashFunc  crypto.Hash
	PublicKey crypto.PublicKey
	// The hash algorithm used during signature creation
	SignatureHashFunc crypto.Hash
}

func (tr *TrustedRoot) TSACertificateAuthorities() []CertificateAuthority {
	return tr.tsaCertAuthorities
}

func (tr *TrustedRoot) FulcioCertificateAuthorities() []CertificateAuthority {
	return tr.fulcioCertAuthorities
}

func (tr *TrustedRoot) TlogAuthorities() map[string]*TlogAuthority {
	return tr.tlogAuthorities
}

func (tr *TrustedRoot) CTlogAuthorities() map[string]*TlogAuthority {
	return tr.ctLogAuthorities
}

func NewTrustedRootFromProtobuf(protobufTrustedRoot *prototrustroot.TrustedRoot) (trustedRoot *TrustedRoot, err error) {
	if protobufTrustedRoot.GetMediaType() != TrustedRootMediaType01 {
		return nil, fmt.Errorf("unsupported TrustedRoot media type: %s", protobufTrustedRoot.GetMediaType())
	}

	trustedRoot = &TrustedRoot{trustedRoot: protobufTrustedRoot}
	trustedRoot.tlogAuthorities, err = ParseTlogAuthorities(protobufTrustedRoot.GetTlogs())
	if err != nil {
		return nil, err
	}

	trustedRoot.fulcioCertAuthorities, err = ParseCertificateAuthorities(protobufTrustedRoot.GetCertificateAuthorities())
	if err != nil {
		return nil, err
	}

	trustedRoot.tsaCertAuthorities, err = ParseCertificateAuthorities(protobufTrustedRoot.GetTimestampAuthorities())
	if err != nil {
		return nil, err
	}

	trustedRoot.ctLogAuthorities, err = ParseTlogAuthorities(protobufTrustedRoot.GetCtlogs())
	if err != nil {
		return nil, err
	}

	return trustedRoot, nil
}

func ParseTlogAuthorities(tlogs []*prototrustroot.TransparencyLogInstance) (tlogAuthorities map[string]*TlogAuthority, err error) {
	tlogAuthorities = make(map[string]*TlogAuthority)
	for _, tlog := range tlogs {
		if tlog.GetHashAlgorithm() != protocommon.HashAlgorithm_SHA2_256 {
			return nil, fmt.Errorf("unsupported tlog hash algorithm: %s", tlog.GetHashAlgorithm())
		}
		if tlog.GetLogId() == nil {
			return nil, fmt.Errorf("tlog missing log ID")
		}
		if tlog.GetLogId().GetKeyId() == nil {
			return nil, fmt.Errorf("tlog missing log ID key ID")
		}
		encodedKeyID := hex.EncodeToString(tlog.GetLogId().GetKeyId())

		if tlog.GetPublicKey() == nil {
			return nil, fmt.Errorf("tlog missing public key")
		}
		if tlog.GetPublicKey().GetRawBytes() == nil {
			return nil, fmt.Errorf("tlog missing public key raw bytes")
		}

		var hashFunc crypto.Hash
		switch tlog.GetHashAlgorithm() {
		case protocommon.HashAlgorithm_SHA2_256:
			hashFunc = crypto.SHA256
		default:
			return nil, fmt.Errorf("unsupported hash function for the tlog")
		}

		switch tlog.GetPublicKey().GetKeyDetails() {
		case protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256:
			key, err := x509.ParsePKIXPublicKey(tlog.GetPublicKey().GetRawBytes())
			if err != nil {
				return nil, err
			}
			var ecKey *ecdsa.PublicKey
			var ok bool
			if ecKey, ok = key.(*ecdsa.PublicKey); !ok {
				return nil, fmt.Errorf("tlog public key is not ECDSA P256")
			}
			tlogAuthorities[encodedKeyID] = &TlogAuthority{
				BaseURL:           tlog.GetBaseUrl(),
				ID:                tlog.GetLogId().GetKeyId(),
				HashFunc:          hashFunc,
				PublicKey:         ecKey,
				SignatureHashFunc: crypto.SHA256,
			}
			if validFor := tlog.GetPublicKey().GetValidFor(); validFor != nil {
				if validFor.GetStart() != nil {
					tlogAuthorities[encodedKeyID].ValidityPeriodStart = validFor.GetStart().AsTime()
				} else {
					return nil, fmt.Errorf("tlog missing public key validity period start time")
				}
				if validFor.GetEnd() != nil {
					tlogAuthorities[encodedKeyID].ValidityPeriodEnd = validFor.GetEnd().AsTime()
				}
			} else {
				return nil, fmt.Errorf("tlog missing public key validity period")
			}
		default:
			return nil, fmt.Errorf("unsupported tlog public key type: %s", tlog.GetPublicKey().GetKeyDetails())
		}
	}
	return tlogAuthorities, nil
}

func ParseCertificateAuthorities(certAuthorities []*prototrustroot.CertificateAuthority) (certificateAuthorities []CertificateAuthority, err error) {
	certificateAuthorities = make([]CertificateAuthority, len(certAuthorities))
	for i, certAuthority := range certAuthorities {
		certificateAuthority, err := ParseCertificateAuthority(certAuthority)
		if err != nil {
			return nil, err
		}
		certificateAuthorities[i] = *certificateAuthority
	}
	return certificateAuthorities, nil
}

func ParseCertificateAuthority(certAuthority *prototrustroot.CertificateAuthority) (certificateAuthority *CertificateAuthority, err error) {
	if certAuthority == nil {
		return nil, fmt.Errorf("CertificateAuthority is nil")
	}
	certChain := certAuthority.GetCertChain()
	if certChain == nil {
		return nil, fmt.Errorf("CertificateAuthority missing cert chain")
	}
	chainLen := len(certChain.GetCertificates())
	if chainLen < 1 {
		return nil, fmt.Errorf("CertificateAuthority cert chain is empty")
	}

	certificateAuthority = &CertificateAuthority{}
	for i, cert := range certChain.GetCertificates() {
		parsedCert, err := x509.ParseCertificate(cert.RawBytes)
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0 && !parsedCert.IsCA:
			certificateAuthority.Leaf = parsedCert
		case i < chainLen-1:
			certificateAuthority.Intermediates = append(certificateAuthority.Intermediates, parsedCert)
		case i == chainLen-1:
			certificateAuthority.Root = parsedCert
		}
	}
	validFor := certAuthority.GetValidFor()
	if validFor != nil {
		start := validFor.GetStart()
		if start != nil {
			certificateAuthority.ValidityPeriodStart = start.AsTime()
		}
		end := validFor.GetEnd()
		if end != nil {
			certificateAuthority.ValidityPeriodEnd = end.AsTime()
		}
	}

	// TODO: Should we inspect/enforce ca.Subject and ca.Uri?
	// TODO: Handle validity period (ca.ValidFor)

	return certificateAuthority, nil
}

func NewTrustedRootFromPath(path string) (*TrustedRoot, error) {
	trustedrootJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return NewTrustedRootFromJSON(trustedrootJSON)
}

// NewTrustedRootFromJSON returns the Sigstore trusted root.
func NewTrustedRootFromJSON(rootJSON []byte) (*TrustedRoot, error) {
	pbTrustedRoot, err := NewTrustedRootProtobuf(rootJSON)
	if err != nil {
		return nil, err
	}

	return NewTrustedRootFromProtobuf(pbTrustedRoot)
}

// NewTrustedRootProtobuf returns the Sigstore trusted root as a protobuf.
func NewTrustedRootProtobuf(rootJSON []byte) (*prototrustroot.TrustedRoot, error) {
	pbTrustedRoot := &prototrustroot.TrustedRoot{}
	err := protojson.Unmarshal(rootJSON, pbTrustedRoot)
	if err != nil {
		return nil, err
	}
	return pbTrustedRoot, nil
}
