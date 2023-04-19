package bundle

import protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"

func GetTlogOptions(artifactVerificationOptions *protoverification.ArtifactVerificationOptions) *protoverification.ArtifactVerificationOptions_TlogOptions {
	if artifactVerificationOptions != nil && artifactVerificationOptions.TlogOptions != nil {
		return artifactVerificationOptions.TlogOptions
	}
	return &protoverification.ArtifactVerificationOptions_TlogOptions{
		Threshold:                 1,
		PerformOnlineVerification: false,
		Disable:                   false,
	}
}

func GetCtlogOptions(artifactVerificationOptions *protoverification.ArtifactVerificationOptions) *protoverification.ArtifactVerificationOptions_CtlogOptions {
	if artifactVerificationOptions != nil && artifactVerificationOptions.CtlogOptions != nil {
		return artifactVerificationOptions.CtlogOptions
	}
	return &protoverification.ArtifactVerificationOptions_CtlogOptions{
		Threshold:   1,
		DetachedSct: false,
		Disable:     false,
	}
}

func GetTsaOptions(artifactVerificationOptions *protoverification.ArtifactVerificationOptions) *protoverification.ArtifactVerificationOptions_TimestampAuthorityOptions {
	if artifactVerificationOptions != nil && artifactVerificationOptions.TsaOptions != nil {
		return artifactVerificationOptions.TsaOptions
	}
	return &protoverification.ArtifactVerificationOptions_TimestampAuthorityOptions{
		Threshold: 1,
		Disable:   false,
	}
}
