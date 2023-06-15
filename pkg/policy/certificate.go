package policy

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

type CertificateSignaturePolicy struct {
	trustedRoot root.TrustedRoot
}

func (p *CertificateSignaturePolicy) VerifyPolicy(entity SignedEntity) error {
	certs, err := entity.CertificateChain()
	if err != nil || len(certs) == 0 {
		return errors.New("artifact does not provide a certificate")
	}
	leafCert := certs[0]

	verifier, err := signature.LoadVerifier(leafCert.PublicKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}

	envelope, err := entity.Envelope()
	if err != nil {
		return errors.New("artifact does not provide an envelope")
	}
	err = verifyEnvelope(envelope, verifier)
	if err != nil {
		return fmt.Errorf("envelope verification failed: %w", err)
	}

	for _, ca := range p.trustedRoot.FulcioCertificateAuthorities() {
		if !ca.ValidityPeriodStart.IsZero() && leafCert.NotBefore.Before(ca.ValidityPeriodStart) {
			continue
		}
		if !ca.ValidityPeriodEnd.IsZero() && leafCert.NotAfter.After(ca.ValidityPeriodEnd) {
			continue
		}

		rootCertPool := x509.NewCertPool()
		rootCertPool.AddCert(ca.Root)
		intermediateCertPool := x509.NewCertPool()
		for _, cert := range ca.Intermediates {
			intermediateCertPool.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			// CurrentTime is intentionally set to the leaf certificate's
			// NotBefore time to ensure that we can continue to verify
			// old bundles after they expire.
			CurrentTime:   certs[0].NotBefore,
			Roots:         rootCertPool,
			Intermediates: intermediateCertPool,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageCodeSigning,
			},
		}

		_, err = leafCert.Verify(opts)
		if err == nil {
			return nil
		}
	}

	return errors.New("certificate verification failed")
}

func verifyEnvelope(envelope *dsse.Envelope, verifier signature.Verifier) error {
	pub, err := verifier.PublicKey()
	if err != nil {
		return err
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
	})
	if err != nil {
		return err
	}
	_, err = envVerifier.Verify(context.TODO(), envelope)
	if err != nil {
		return err
	}
	return nil
}

func NewCertificateSignaturePolicy(trustedRoot root.TrustedRoot) *CertificateSignaturePolicy {
	return &CertificateSignaturePolicy{
		trustedRoot: trustedRoot,
	}
}

type CertificateOIDCPolicy struct {
	expectedOIDC string
}

func (p *CertificateOIDCPolicy) VerifyPolicy(entity SignedEntity) error {
	certs, err := entity.CertificateChain()
	if err != nil || len(certs) == 0 {
		return errors.New("artifact does not provide a certificate")
	}
	leafCert := certs[0]

	for _, extension := range leafCert.Extensions {
		if extension.Id.String() == "1.3.6.1.4.1.57264.1.1" {
			if string(extension.Value) == p.expectedOIDC {
				return nil
			}
			return fmt.Errorf("Signing certificate Issuer OID %s does not match expected OIDC issuer %s", string(extension.Value), p.expectedOIDC)
		}
	}

	return errors.New("Certificate does not contain Issuer OID")
}

func NewCertificateOIDCPolicy(expectedOIDC string) *CertificateOIDCPolicy {
	return &CertificateOIDCPolicy{
		expectedOIDC: expectedOIDC,
	}
}

type CertificateSANPolicy struct {
	expectedSAN string
}

func (p *CertificateSANPolicy) VerifyPolicy(entity SignedEntity) error {
	certs, err := entity.CertificateChain()
	if err != nil || len(certs) == 0 {
		return errors.New("artifact does not provide a certificate")
	}
	leafCert := certs[0]

	if len(leafCert.URIs) > 0 && leafCert.URIs[0].String() != p.expectedSAN {
		return fmt.Errorf("Signing certificate subject %s does not match expected subject %s", leafCert.URIs[0].String(), p.expectedSAN)
	}

	return nil
}

func NewCertificateSANPolicy(expectedSAN string) *CertificateSANPolicy {
	return &CertificateSANPolicy{
		expectedSAN: expectedSAN,
	}
}
