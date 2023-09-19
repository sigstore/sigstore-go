package verify

import (
	"errors"
	"fmt"
	"time"

	"github.com/github/sigstore-verifier/pkg/fulcio/certificate"
	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/in-toto/in-toto-golang/in_toto"
)

type SignedEntityVerifier struct {
	trustedMaterial root.TrustedMaterial
	config          VerifierConfig
}

type VerifierConfig struct { // nolint: revive
	performOnlineVerification          bool
	weExpectSignedTimestamps           bool
	signedTimestampThreshold           int
	weExpectTlogEntries                bool
	tlogEntriesThreshold               int
	weExpectSCTs                       bool
	ctlogEntriesThreshold              int
	weDoNotExpectAnyObserverTimestamps bool
}

type VerifierConfigurator func(*VerifierConfig) // nolint: revive

// NewSignedEntityVerifier creates a new SignedEntityVerifier. It takes a
// root.TrustedMaterial, which contains a set of trusted public keys and
// certificates, and a set of VerifierConfigurators, which set the config
// that determines the behaviour of the Verify function.
func NewSignedEntityVerifier(trustedMaterial root.TrustedMaterial, options ...VerifierConfigurator) (*SignedEntityVerifier, error) {
	c := VerifierConfig{}

	for _, opt := range options {
		opt(&c)
	}

	err := c.Validate()
	if err != nil {
		return nil, err
	}

	v := &SignedEntityVerifier{
		trustedMaterial: trustedMaterial,
		config:          c,
	}

	return v, nil
}

// WithOnlineVerification configures the SignedEntityVerifier to perform
// online verification when verifying Transparency Log entries and
// Signed Certificate Timestamps.
func WithOnlineVerification() VerifierConfigurator {
	return func(c *VerifierConfig) {
		c.performOnlineVerification = true
	}
}

// WithSignedTimestamps configures the SignedEntityVerifier to expect RFC 3161
// timestamps from a Timestamp Authority, verify them using the TrustedMaterial's
// TSACertificateAuthorities(), and, if it exists, use the resulting timestamp(s)
// to verify the Fulcio certificate.
func WithSignedTimestamps(threshold int) VerifierConfigurator {
	return func(c *VerifierConfig) {
		c.weExpectSignedTimestamps = true
		if threshold < 1 {
			c.signedTimestampThreshold = 1
		} else {
			c.signedTimestampThreshold = threshold
		}
	}
}

// WithTransparencyLog configures the SignedEntityVerifier to expect
// Transparency Log entries, verify them using the TrustedMaterial's
// TlogAuthorities(), and, if it exists, use the resulting Inclusion timestamp(s)
// to verify the Fulcio certificate.
func WithTransparencyLog(threshold int) VerifierConfigurator {
	return func(c *VerifierConfig) {
		c.weExpectTlogEntries = true
		if threshold < 1 {
			c.tlogEntriesThreshold = 1
		} else {
			c.tlogEntriesThreshold = threshold
		}
	}
}

// WithSignedCertificateTimestamps configures the SignedEntityVerifier to
// expect the Fulcio certificate to have a SignedCertificateTimestamp, and
// verify it using the TrustedMaterial's CTLogAuthorities().
func WithSignedCertificateTimestamps(threshold int) VerifierConfigurator {
	return func(c *VerifierConfig) {
		c.weExpectSCTs = true
		if threshold < 1 {
			c.ctlogEntriesThreshold = 1
		} else {
			c.ctlogEntriesThreshold = threshold
		}
	}
}

// WithoutAnyObserverTimestampsInsecure configures the SignedEntityVerifier to not expect
// any timestamps from either a Timestamp Authority or a Transparency Log.
//
// A SignedEntity without a trusted "observer" timestamp to verify the attached
// Fulcio certificate can't provide the same kind of integrity guarantee.
//
// Do not enable this if you don't know what you are doing.
func WithoutAnyObserverTimestampsInsecure() VerifierConfigurator {
	return func(c *VerifierConfig) {
		c.weDoNotExpectAnyObserverTimestamps = true
	}
}

func (c *VerifierConfig) Validate() error {
	if !c.weExpectSignedTimestamps && !c.weExpectTlogEntries && !c.weDoNotExpectAnyObserverTimestamps {
		return errors.New("when initializing a new SignedEntityVerifier, you must specify at least one, or both, of WithSignedTimestamps() or WithTransparencyLog()")
	}

	return nil
}

type VerificationResult struct {
	Version            int                           `json:"version"`
	Statement          *in_toto.Statement            `json:"statement,omitempty"`
	Signature          *SignatureVerificationResult  `json:"signature,omitempty"`
	VerifiedTimestamps []TimestampVerificationResult `json:"verifiedTimestamps"`
	VerifiedIdentity   *CertificateIdentity          `json:"verifiedIdentity,omitempty"`
}

type SignatureVerificationResult struct {
	PublicKeyID *[]byte              `json:"publicKeyId,omitempty"`
	Certificate *certificate.Summary `json:"certificate,omitempty"`
}

type TimestampVerificationResult struct {
	Type      string    `json:"type"`
	URI       string    `json:"uri"`
	Timestamp time.Time `json:"timestamp"`
}

func NewVerificationResult() *VerificationResult {
	return &VerificationResult{
		Version: 20230823,
	}
}

type PolicyOptionConfigurator func(*PolicyOptions)

type PolicyOptions struct {
	verifyIdentities      bool
	CertificateIdentities CertificateIdentities
	// TODO:
	// verifyArtifact        bool
	// Artifact              []byte
}

// WithCertificateIdentity allows the caller of Verify to enforce that the
// SignedEntity being verified was created by a given identity, as defined by
// the Fulcio certificate embedded in the entity. If this policy is enabled,
// but the SignedEntity does not have a certificate, verification will fail.
//
// Providing this function multiple times will concatenate the provided
// CertificateIdentity to the list of identities being checked.
//
// If all of the provided CertificateIdentities fail to match the Fulcio
// certificate, then verification will fail. If *any* CertificateIdentity
// matches, then verification will succeed. Therefore, each CertificateIdentity
// provided to this function must define a "sufficient" identity.
//
// The CertificateIdentity struct allows callers to specify:
// - The exact value, or Regexp, of the SubjectAlternativeName
// - The exact value of any Fulcio OID X.509 extension, i.e. Issuer
//
// For convenience, consult the NewShortCertificateIdentity function.
//
// Enabling this policy is highly recommended, especially to assert that the
// OID Issuer matches the expected value.
func WithCertificateIdentity(identity CertificateIdentity) PolicyOptionConfigurator {
	return func(v *PolicyOptions) {
		v.verifyIdentities = true
		v.CertificateIdentities = append(v.CertificateIdentities, identity)
	}
}

// Verify checks the cryptographic integrity of a given SignedEntity according
// to the options configured in the NewSignedEntityVerifier. Its purpose is to
// determine whether the SignedEntity was created by a Sigstore deployment we
// trust, as defined by keys in our TrustedMaterial.
//
// Verify then creates a VerificationResult struct whose contents' integrity
// have been verified. At the function caller's discretion, Verify may then
// verify the contents of the VerificationResults using supplied PolicyOptions.
// See WithCertificateIdentity for more details.
//
// If no policy options are provided, callers of this function SHOULD:
//   - (if the signed entity has a certificate) verify that its Subject Alternate
//     Name matches a trusted identity, and that its Issuer field matches an
//     expected value
//   - (if the signed entity has a dsse envelope) verify that the envelope's
//     statement's subject matches the artifact being verified
func (v *SignedEntityVerifier) Verify(entity SignedEntity, options ...PolicyOptionConfigurator) (*VerificationResult, error) {
	policy := &PolicyOptions{}
	for _, opt := range options {
		opt(policy)
	}

	// Let's go by the spec: https://docs.google.com/document/d/1kbhK2qyPPk8SLavHzYSDM8-Ueul9_oxIMVFuWMWKz0E/edit#heading=h.msyyz1cr5bcs
	// > ## Establishing a Time for the Signature
	// > First, establish a time for the signature. This timestamp is required to validate the certificate chain, so this step comes first.

	verifiedTimestamps, err := v.VerifyObserverTimestamps(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to verify timestamps: %w", err)
	}

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch verification content: %w", err)
	}

	var signedWithCertificate bool
	var certSummary certificate.Summary

	// If the bundle was signed with a long-lived key, and does not have a Fulcio certificate,
	// then skip the certificate verification steps
	if leafCert, ok := verificationContent.HasCertificate(); ok {
		signedWithCertificate = true

		// From spec:
		// > ## Certificate
		// > …
		// > The Verifier MUST perform certification path validation (RFC 5280 §6) of the certificate chain with the pre-distributed Fulcio root certificate(s) as a trust anchor, but with a fake “current time.” If a timestamp from the timestamping service is available, the Verifier MUST perform path validation using the timestamp from the Timestamping Service. If a timestamp from the Transparency Service is available, the Verifier MUST perform path validation using the timestamp from the Transparency Service. If both are available, the Verifier performs path validation twice. If either fails, verification fails.

		for _, verifiedTs := range verifiedTimestamps {
			// verify the leaf certificate against the root
			err = VerifyLeafCertificate(verifiedTs.Timestamp, leafCert, v.trustedMaterial)
			if err != nil {
				return nil, fmt.Errorf("failed to verify leaf certificate: %w", err)
			}
		}

		// From spec:
		// > Unless performing online verification (see §Alternative Workflows), the Verifier MUST extract the  SignedCertificateTimestamp embedded in the leaf certificate, and verify it as in RFC 9162 §8.1.3, using the verification key from the Certificate Transparency Log.

		if v.config.weExpectSCTs {
			err = VerifySignedCertificateTimestamp(&leafCert, v.config.ctlogEntriesThreshold, v.trustedMaterial)
			if err != nil {
				return nil, fmt.Errorf("failed to verify signed certificate timestamp: %w", err)
			}
		}

		certSummary, err = certificate.SummarizeCertificate(&leafCert)
		if err != nil {
			return nil, fmt.Errorf("failed to summarize certificate: %w", err)
		}
	}

	// From spec:
	// > ## Signature Verification
	// > The Verifier MUST verify the provided signature for the constructed payload against the key in the leaf of the certificate chain.

	// TODO: if the SignatureContent is a MessageSignature, then we MUST provide the artifact []byte
	// to its Verify function, because if it was signed with the ed25519 algo it won't work otherwise.
	// At present we have punted figuring that out; we can't _always_ require the artifact, because
	// in certain contexts we may not have access to the artifact. Something in this func signature
	// will have to change, but what exactly is not clear yet.

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature content: %w", err)
	}

	err = VerifySignature(sigContent, verificationContent, v.trustedMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	// Hooray! We've verified all of the entity's constituent parts! 🎉 🥳
	// Now we can construct the results object accordingly.
	result := NewVerificationResult()
	if signedWithCertificate {
		result.Signature = &SignatureVerificationResult{
			Certificate: &certSummary,
		}
	}

	// SignatureContent can be either an Envelope or a MessageSignature.
	// If it's an Envelope, let's pop the Statement for our results:
	if envelope, ok := sigContent.HasEnvelope(); ok {
		stmt, err := envelope.GetStatement()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch envelope statement: %w", err)
		}

		result.Statement = stmt
	}

	result.VerifiedTimestamps = verifiedTimestamps

	// Now that the signed entity's crypto material has been verified, and the
	// result struct has been constructed, we can optionally enforce some
	// additional policies:
	// --------------------

	// From ## Certificate section,
	// >The Verifier MUST then check the certificate against the verification policy. Details on how to do this depend on the verification policy, but the Verifier SHOULD check the Issuer X.509 extension (OID 1.3.6.1.4.1.57264.1.1) at a minimum, and will in most cases check the SubjectAlternativeName as well. See  Spec: Fulcio §TODO for example checks on the certificate.
	if policy.verifyIdentities {
		if !signedWithCertificate {
			// We got asked to verify identities, but the entity was not signed with
			// a certificate. That's a problem!
			return nil, errors.New("can't verify certificate identities: entity was not signed with a certificate")
		}

		matchingCertID, err := policy.CertificateIdentities.Verify(certSummary)
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate identity: %w", err)
		}

		result.VerifiedIdentity = matchingCertID
	}

	return result, nil
}

// VerifyObserverTimestamps verifies TlogEntries and SignedTimestamps, if we
// expect them, and returns a slice of verified results, which embed the actual
// time.Time value. This value can then be used to verify certificates, if any.
// In order to be verifiable, a SignedEntity must have at least one verified
// "observer timestamp".
func (v *SignedEntityVerifier) VerifyObserverTimestamps(entity SignedEntity) ([]TimestampVerificationResult, error) {
	verifiedTimestamps := []TimestampVerificationResult{}

	// From spec:
	// > … if verification or timestamp parsing fails, the Verifier MUST abort
	if v.config.weExpectSignedTimestamps {
		tsaVerifier := NewTimestampAuthorityVerifier(v.trustedMaterial, v.config.signedTimestampThreshold)
		verifiedSignedTimestamps, err := tsaVerifier.Verify(entity)
		if err != nil {
			return nil, err
		}

		for _, vts := range verifiedSignedTimestamps {
			verifiedTimestamps = append(verifiedTimestamps, TimestampVerificationResult{Type: "TimestampAuthority", URI: "TODO", Timestamp: vts})
		}
	}

	if v.config.weExpectTlogEntries {
		tlogVerifier := NewArtifactTransparencyLogVerifier(v.trustedMaterial, v.config.tlogEntriesThreshold, v.config.performOnlineVerification)
		verifiedTlogTimestamps, err := tlogVerifier.Verify(entity)
		if err != nil {
			return nil, err
		}

		for _, vts := range verifiedTlogTimestamps {
			verifiedTimestamps = append(verifiedTimestamps, TimestampVerificationResult{Type: "Tlog", URI: "TODO", Timestamp: vts})
		}
	}

	if v.config.weDoNotExpectAnyObserverTimestamps {
		// if we have a cert, let's pop the leafcert's NotBefore
		verificationContent, err := entity.VerificationContent()
		if err != nil {
			return nil, err
		}

		if leafCert, ok := verificationContent.HasCertificate(); ok {
			verifiedTimestamps = append(verifiedTimestamps, TimestampVerificationResult{Type: "LeafCert.NotBefore", URI: "", Timestamp: leafCert.NotBefore})
		} else {
			// no cert? use current time
			verifiedTimestamps = append(verifiedTimestamps, TimestampVerificationResult{Type: "CurrentTime", URI: "", Timestamp: time.Now()})
		}
	}

	if len(verifiedTimestamps) == 0 {
		return nil, fmt.Errorf("no valid observer timestamps found")
	}

	return verifiedTimestamps, nil
}
