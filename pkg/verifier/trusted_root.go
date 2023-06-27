package verifier

import (
	"github.com/github/sigstore-verifier/pkg/root"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

type TrustedRootVerifier struct {
	subPolicies []Verifier
}

func (p *TrustedRootVerifier) Verify(entity SignedEntity) error {
	return Verify(entity, p.subPolicies...)
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

func NewTrustedRootVerifier(trustedRoot root.TrustedRoot, opts *protoverification.ArtifactVerificationOptions) *TrustedRootVerifier {
	subPolicies := []Verifier{NewCertificateSignatureVerifier(trustedRoot)}

	signers := opts.GetCertificateIdentities()
	if signers != nil && len(signers.Identities) > 0 {
		expectedOIDC := signers.Identities[0].Issuer
		if expectedOIDC != "" {
			subPolicies = append(subPolicies, NewCertificateOIDCVerifier(expectedOIDC))
		}

		if signers.Identities[0].San != nil {
			expectedSAN := signers.Identities[0].San.GetValue()
			if expectedSAN != "" {
				subPolicies = append(subPolicies, NewCertificateSANVerifier(expectedSAN))
			}
		}
	}

	if tsaOpts := opts.GetTsaOptions(); tsaOpts != nil {
		if !tsaOpts.GetDisable() {
			subPolicies = append(subPolicies, NewTimestampAuthorityVerifier(trustedRoot, int(tsaOpts.GetThreshold())))
		}
	}
	if tlogOptions := opts.GetTlogOptions(); tlogOptions != nil {
		if !tlogOptions.GetDisable() {
			subPolicies = append(subPolicies, NewArtifactTransparencyLogVerifier(trustedRoot, int(tlogOptions.GetThreshold())))
		}
	}
	if ctlogOptions := opts.GetCtlogOptions(); ctlogOptions != nil {
		if !ctlogOptions.GetDisable() {
			subPolicies = append(subPolicies, NewCertificateTransparencyLogVerifier(trustedRoot, int(ctlogOptions.GetThreshold())))
		}
	}

	return &TrustedRootVerifier{subPolicies}
}
