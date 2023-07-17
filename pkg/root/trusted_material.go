package root

import (
	"fmt"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
)

type TrustedMaterial interface {
	TSACertificateAuthorities() []CertificateAuthority
	FulcioCertificateAuthorities() []CertificateAuthority
	TlogVerifiers() map[string]*TlogVerifier
	PublicKeyVerifier(string) (ValidityPeriodVerifier, error)
}

type BaseTrustedMaterial struct{}

func (b *BaseTrustedMaterial) TSACertificateAuthorities() []CertificateAuthority {
	return []CertificateAuthority{}
}

func (b *BaseTrustedMaterial) FulcioCertificateAuthorities() []CertificateAuthority {
	return []CertificateAuthority{}
}

func (b *BaseTrustedMaterial) TlogVerifiers() map[string]*TlogVerifier {
	return map[string]*TlogVerifier{}
}

func (b *BaseTrustedMaterial) PublicKeyVerifier(_ string) (ValidityPeriodVerifier, error) {
	return nil, fmt.Errorf("public key verifier not found")
}

type TrustedMaterialCollection []TrustedMaterial

var _ TrustedMaterial = TrustedMaterialCollection{}

func (tmc TrustedMaterialCollection) PublicKeyVerifier(keyID string) (ValidityPeriodVerifier, error) {
	for _, tm := range tmc {
		verifier, err := tm.PublicKeyVerifier(keyID)
		if err == nil {
			return verifier, nil
		}
	}
	return nil, fmt.Errorf("public key verifier not found for keyID: %s", keyID)
}

func (tmc TrustedMaterialCollection) TSACertificateAuthorities() []CertificateAuthority {
	var certAuthorities []CertificateAuthority
	for _, tm := range tmc {
		certAuthorities = append(certAuthorities, tm.TSACertificateAuthorities()...)
	}
	return certAuthorities
}

func (tmc TrustedMaterialCollection) FulcioCertificateAuthorities() []CertificateAuthority {
	var certAuthorities []CertificateAuthority
	for _, tm := range tmc {
		certAuthorities = append(certAuthorities, tm.FulcioCertificateAuthorities()...)
	}
	return certAuthorities
}

func (tmc TrustedMaterialCollection) TlogVerifiers() map[string]*TlogVerifier {
	tlogVerifiers := make(map[string]*TlogVerifier)
	for _, tm := range tmc {
		for keyID, tlogVerifier := range tm.TlogVerifiers() {
			tlogVerifiers[keyID] = tlogVerifier
		}
	}
	return tlogVerifiers
}

type ValidityPeriodChecker interface {
	ValidAtTime(time.Time) bool
}

type ValidityPeriodVerifier interface {
	ValidityPeriodChecker
	signature.Verifier
}
