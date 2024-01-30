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
	"crypto"
	"crypto/x509"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type CertificateChain struct {
	Certificates []*x509.Certificate
}

type PublicKey struct {
	HintString string
}

func (pk PublicKey) Hint() string {
	return pk.HintString
}

func (cc *CertificateChain) CompareKey(key any, _ root.TrustedMaterial) bool {
	x509Key, ok := key.(*x509.Certificate)
	if !ok {
		return false
	}

	return cc.Certificates[0].Equal(x509Key)
}

func (cc *CertificateChain) ValidAtTime(t time.Time, _ root.TrustedMaterial) bool {
	return !(cc.Certificates[0].NotAfter.Before(t) || cc.Certificates[0].NotBefore.After(t))
}

func (cc *CertificateChain) HasCertificate() (x509.Certificate, bool) {
	return *cc.Certificates[0], true
}

func (pk *PublicKey) HasCertificate() (x509.Certificate, bool) {
	return x509.Certificate{}, false
}

func (cc *CertificateChain) HasPublicKey() (verify.PublicKeyProvider, bool) {
	return PublicKey{}, false
}

func (pk *PublicKey) HasPublicKey() (verify.PublicKeyProvider, bool) {
	return *pk, true
}

func (pk *PublicKey) CompareKey(key any, tm root.TrustedMaterial) bool {
	verifier, err := tm.PublicKeyVerifier(pk.HintString)
	if err != nil {
		return false
	}
	pubKey, err := verifier.PublicKey()
	if err != nil {
		return false
	}
	if equaler, ok := key.(interface{ Equal(x crypto.PublicKey) bool }); ok {
		return equaler.Equal(pubKey)
	}
	return false
}

func (pk *PublicKey) ValidAtTime(t time.Time, tm root.TrustedMaterial) bool {
	verifier, err := tm.PublicKeyVerifier(pk.HintString)
	if err != nil {
		return false
	}
	return verifier.ValidAtTime(t)
}
