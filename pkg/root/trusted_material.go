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
	PublicKeyVerifier(string) (TimeConstrainedVerifier, error)
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

func (b *BaseTrustedMaterial) PublicKeyVerifier(_ string) (TimeConstrainedVerifier, error) {
	return nil, fmt.Errorf("public key verifier not found")
}

type TrustedMaterialCollection []TrustedMaterial

// Ensure types implement interfaces
var _ TrustedMaterial = &BaseTrustedMaterial{}
var _ TrustedMaterial = TrustedMaterialCollection{}

func (tmc TrustedMaterialCollection) PublicKeyVerifier(keyID string) (TimeConstrainedVerifier, error) {
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

type TimeConstrainedVerifier interface {
	ValidityPeriodChecker
	signature.Verifier
}

type TrustedPublicKeyMaterial struct {
	BaseTrustedMaterial
	publicKeyVerifier func(string) (TimeConstrainedVerifier, error)
}

func (tr *TrustedPublicKeyMaterial) PublicKeyVerifier(keyID string) (TimeConstrainedVerifier, error) {
	return tr.publicKeyVerifier(keyID)
}

func NewTrustedPublicKeyMaterial(publicKeyVerifier func(string) (TimeConstrainedVerifier, error)) *TrustedPublicKeyMaterial {
	return &TrustedPublicKeyMaterial{
		publicKeyVerifier: publicKeyVerifier,
	}
}

// ExpiringKey is a TimeConstrainedVerifier with a static validity period.
type ExpiringKey struct {
	signature.Verifier
	validityPeriodStart time.Time
	validityPeriodEnd   time.Time
}

var _ TimeConstrainedVerifier = &ExpiringKey{}

// ValidAtTime returns true if the key is valid at the given time. If the
// validity period start time is not set, the key is considered valid for all
// times before the end time. Likewise, if the validity period end time is not
// set, the key is considered valid for all times after the start time.
func (k *ExpiringKey) ValidAtTime(t time.Time) bool {
	if !k.validityPeriodStart.IsZero() && t.Before(k.validityPeriodStart) {
		return false
	}
	if !k.validityPeriodEnd.IsZero() && t.After(k.validityPeriodEnd) {
		return false
	}
	return true
}

// NewExpiringKey returns a new ExpiringKey with the given validity period
func NewExpiringKey(verifier signature.Verifier, validityPeriodStart, validityPeriodEnd time.Time) *ExpiringKey {
	return &ExpiringKey{
		Verifier:            verifier,
		validityPeriodStart: validityPeriodStart,
		validityPeriodEnd:   validityPeriodEnd,
	}
}

// NewTrustedPublicKeyMaterialFromMapping returns a TrustedPublicKeyMaterial from a map of key IDs to
// ExpiringKeys.
func NewTrustedPublicKeyMaterialFromMapping(trustedPublicKeys map[string]*ExpiringKey) *TrustedPublicKeyMaterial {
	return NewTrustedPublicKeyMaterial(func(keyID string) (TimeConstrainedVerifier, error) {
		expiringKey, ok := trustedPublicKeys[keyID]
		if !ok {
			return nil, fmt.Errorf("public key not found for keyID: %s", keyID)
		}
		return expiringKey, nil
	})
}
