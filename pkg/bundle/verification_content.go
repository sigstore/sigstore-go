package bundle

import (
	"crypto"
	"crypto/x509"
	"time"

	"github.com/github/sigstore-go/pkg/root"
	"github.com/github/sigstore-go/pkg/verify"
)

type CertificateChain struct {
	Certificates []*x509.Certificate
}

type PublicKey struct {
	hint string
}

func (pk PublicKey) Hint() string {
	return pk.hint
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
	verifier, err := tm.PublicKeyVerifier(pk.hint)
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
	verifier, err := tm.PublicKeyVerifier(pk.hint)
	if err != nil {
		return false
	}
	return verifier.ValidAtTime(t)
}
