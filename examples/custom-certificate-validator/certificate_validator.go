// Copyright 2024 The Sigstore Authors.
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

package main

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

type CertificateValidator func(cert *x509.Certificate) error

type ValidatingCertificateAuthority struct {
	root.CertificateAuthority
	validator CertificateValidator
}

func (ca *ValidatingCertificateAuthority) Verify(leafCert *x509.Certificate, observerTimestamp time.Time) ([][]*x509.Certificate, error) {
	if err := ca.validator(leafCert); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}
	return ca.CertificateAuthority.Verify(leafCert, observerTimestamp)
}

type TrustedMaterialWithCertificateValidator struct {
	root.TrustedMaterial
	validator CertificateValidator
}

func NewTrustedMaterialWithCertificateValidation(tm root.TrustedMaterial, validator CertificateValidator) *TrustedMaterialWithCertificateValidator {
	return &TrustedMaterialWithCertificateValidator{
		TrustedMaterial: tm,
		validator:       validator,
	}
}

func (tm *TrustedMaterialWithCertificateValidator) FulcioCertificateAuthorities() []root.CertificateAuthority {
	cas := make([]root.CertificateAuthority, len(tm.TrustedMaterial.FulcioCertificateAuthorities()))
	for i, ca := range tm.TrustedMaterial.FulcioCertificateAuthorities() {
		cas[i] = &ValidatingCertificateAuthority{ca, tm.validator}
	}
	return cas
}

// NewValidatingTrustedMaterial creates a TrustedMaterial that validates certificates against a list of revoked serial numbers.
func NewValidatingTrustedMaterial(trustedMaterial root.TrustedMaterial, revokedSerialNumbers []*big.Int) root.TrustedMaterial {
	return &TrustedMaterialWithCertificateValidator{
		TrustedMaterial: trustedMaterial,
		validator: func(cert *x509.Certificate) error {
			for _, serialNumber := range revokedSerialNumbers {
				if cert.SerialNumber.Cmp(serialNumber) == 0 {
					return fmt.Errorf("certificate with serial number %v is revoked", serialNumber)
				}
			}
			return nil
		},
	}
}
