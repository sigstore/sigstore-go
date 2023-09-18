package bundle

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/verify"
)

type CertificateChain struct {
	Certificates []*x509.Certificate
}

type PublicKey struct {
	Hint string
}

func (pk PublicKey) GetHint() string {
	return pk.Hint
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

func (cc *CertificateChain) VerifySCT(threshold int, trustedMaterial root.TrustedMaterial) error {
	ctlogs := trustedMaterial.CTlogAuthorities()
	fulcioCerts := trustedMaterial.FulcioCertificateAuthorities()

	scts, err := x509util.ParseSCTsFromCertificate(cc.Certificates[0].Raw)
	if err != nil {
		return err
	}

	certChain, err := ctx509.ParseCertificates(cc.Certificates[0].Raw)
	if err != nil {
		return err
	}

	verified := 0
	for _, sct := range scts {
		encodedKeyID := hex.EncodeToString(sct.LogID.KeyID[:])
		key, ok := ctlogs[encodedKeyID]
		if !ok {
			return fmt.Errorf("Unable to find ctlogs key for %s", encodedKeyID)
		}

		for _, fulcioCa := range fulcioCerts {
			if len(fulcioCa.Intermediates) == 0 {
				continue
			}
			fulcioIssuer, err := ctx509.ParseCertificates(fulcioCa.Intermediates[0].Raw)
			if err != nil {
				continue
			}

			fulcioChain := make([]*ctx509.Certificate, len(certChain))
			copy(fulcioChain, certChain)
			fulcioChain = append(fulcioChain, fulcioIssuer...)

			err = ctutil.VerifySCT(key.PublicKey, fulcioChain, sct, true)
			if err == nil {
				verified++
			}
		}
	}

	if verified < threshold {
		return fmt.Errorf("Only able to verify %d SCT entries; unable to meet threshold of %d", verified, threshold)
	}

	return nil
}

func (cc *CertificateChain) GetIssuer() string {
	for _, extension := range cc.Certificates[0].Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}) {
			return string(extension.Value)
		}
	}
	return ""
}

func (cc *CertificateChain) GetSAN() string {
	if len(cc.Certificates[0].URIs) == 0 {
		return ""
	}

	return cc.Certificates[0].URIs[0].String()
}

func (pk *PublicKey) CompareKey(key any, tm root.TrustedMaterial) bool {
	verifier, err := tm.PublicKeyVerifier(pk.Hint)
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
	verifier, err := tm.PublicKeyVerifier(pk.Hint)
	if err != nil {
		return false
	}
	return verifier.ValidAtTime(t)
}

func (pk *PublicKey) VerifySCT(_ int, _ root.TrustedMaterial) error {
	return fmt.Errorf("Keys do not support SCTs")
}

func (pk *PublicKey) GetIssuer() string {
	return ""
}

func (pk *PublicKey) GetSAN() string {
	return ""
}
