package verifier

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

// MultiVerifier is a Verifier that combines one or more other Verifiers.
type MultiVerifier struct {
	subVerifiers []Verifier
}

func (p *MultiVerifier) Verify(entity SignedEntity) error {
	for _, verifier := range p.subVerifiers {
		if err := verifier.Verify(entity); err != nil {
			return NewVerificationError(err)
		}
	}
	return nil
}

func SetExpectedOIDC(opts *protoverification.ArtifactVerificationOptions, expectedOIDC string) {
	signers := opts.GetCertificateIdentities()
	signers.Identities[0].Issuer = expectedOIDC
}

func SetExpectedSAN(opts *protoverification.ArtifactVerificationOptions, expectedSAN string) {
	san := &protocommon.SubjectAlternativeName{
		Identity: &protocommon.SubjectAlternativeName_Value{
			Value: expectedSAN,
		},
	}

	signers := opts.GetCertificateIdentities()
	signers.Identities[0].San = san
}

func GetDefaultOptions() *protoverification.ArtifactVerificationOptions {
	certificateIdentity := &protoverification.CertificateIdentity{
		Issuer: "",
		San:    nil,
	}

	return &protoverification.ArtifactVerificationOptions{
		Signers: &protoverification.ArtifactVerificationOptions_CertificateIdentities{
			CertificateIdentities: &protoverification.CertificateIdentities{
				Identities: []*protoverification.CertificateIdentity{certificateIdentity},
			},
		},
		TlogOptions: &protoverification.ArtifactVerificationOptions_TlogOptions{
			Threshold:                 1,
			PerformOnlineVerification: false,
			Disable:                   false,
		},
		CtlogOptions: &protoverification.ArtifactVerificationOptions_CtlogOptions{
			Threshold:   1,
			DetachedSct: false,
			Disable:     false,
		},
		TsaOptions: &protoverification.ArtifactVerificationOptions_TimestampAuthorityOptions{
			Threshold: 1,
			Disable:   true,
		},
	}
}

func NewVerifier(trustedMaterial root.TrustedMaterial, opts *protoverification.ArtifactVerificationOptions) *MultiVerifier {
	verifiers := []Verifier{NewSignatureVerifier(trustedMaterial)}

	signers := opts.GetCertificateIdentities()
	if signers != nil && len(signers.Identities) > 0 {
		expectedOIDC := signers.Identities[0].Issuer
		if expectedOIDC != "" {
			verifiers = append(verifiers, NewCertificateOIDCVerifier(expectedOIDC))
		}

		if signers.Identities[0].San != nil {
			expectedSAN := signers.Identities[0].San.GetValue()
			if expectedSAN != "" {
				verifiers = append(verifiers, NewCertificateSANVerifier(expectedSAN))
			}
		}
	}

	if tsaOpts := opts.GetTsaOptions(); tsaOpts != nil {
		if !tsaOpts.GetDisable() {
			verifiers = append(verifiers, NewTimestampAuthorityVerifier(trustedMaterial, int(tsaOpts.GetThreshold())))
		}
	}
	if tlogOptions := opts.GetTlogOptions(); tlogOptions != nil {
		if !tlogOptions.GetDisable() {
			verifiers = append(verifiers, NewArtifactTransparencyLogVerifier(trustedMaterial, int(tlogOptions.GetThreshold()), tlogOptions.GetPerformOnlineVerification()))
		}
	}
	if ctlogOptions := opts.GetCtlogOptions(); ctlogOptions != nil {
		if !ctlogOptions.GetDisable() {
			verifiers = append(verifiers, NewCertificateTransparencyLogVerifier(trustedMaterial, int(ctlogOptions.GetThreshold())))
		}
	}

	return &MultiVerifier{verifiers}
}
