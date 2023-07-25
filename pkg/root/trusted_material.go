package root

import (
	"fmt"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
)

type TrustedMaterial interface {
	TSACertificateAuthorities() []CertificateAuthority
	FulcioCertificateAuthorities() []CertificateAuthority
	TlogAuthorities() map[string]*TlogAuthority
	PublicKeyVerifier(string) (ValidityPeriodVerifier, error)
}

type BaseTrustedMaterial struct{}

func (b *BaseTrustedMaterial) TSACertificateAuthorities() []CertificateAuthority {
	return []CertificateAuthority{}
}

func (b *BaseTrustedMaterial) FulcioCertificateAuthorities() []CertificateAuthority {
	return []CertificateAuthority{}
}

func (b *BaseTrustedMaterial) TlogAuthorities() map[string]*TlogAuthority {
	return map[string]*TlogAuthority{}
}

func (b *BaseTrustedMaterial) PublicKeyVerifier(_ string) (ValidityPeriodVerifier, error) {
	return nil, fmt.Errorf("public key verifier not found")
}

type TrustedMaterialCollection []TrustedMaterial

// Ensure types implement interfaces
var _ TrustedMaterial = &BaseTrustedMaterial{}
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

func (tmc TrustedMaterialCollection) TlogAuthorities() map[string]*TlogAuthority {
	tlogAuthorities := make(map[string]*TlogAuthority)
	for _, tm := range tmc {
		for keyID, tlogVerifier := range tm.TlogAuthorities() {
			tlogAuthorities[keyID] = tlogVerifier
		}
	}
	return tlogAuthorities
}

type ValidityPeriodChecker interface {
	ValidAtTime(time.Time) bool
}

type ValidityPeriodVerifier interface {
	ValidityPeriodChecker
	signature.Verifier
}
