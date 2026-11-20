// Copyright 2026 The Sigstore Authors.
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

package verify

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/formats/proof"
)

// IdentityVerificationResult holds the verified outputs of an IdentityVerifier,
// PKIVerifier, or KeyVerifier check.
type IdentityVerificationResult struct {
	Verified         bool
	Timestamps       []time.Time
	Statement        *in_toto.Statement
	VerifiedIdentity *CertificateIdentity
}

// IdentityVerifier verifies transparent signatures logged with an OIDC identity token
// or a public key credential.
type IdentityVerifier struct {
	trustedMaterial root.TrustedMaterial
}

// IdentityVerifierOption configures an IdentityVerifier.
type IdentityVerifierOption func(*IdentityVerifier) error

// NewIdentityVerifier creates a new IdentityVerifier backed by the provided TrustedMaterial.
func NewIdentityVerifier(trustedMaterial root.TrustedMaterial, options ...IdentityVerifierOption) (*IdentityVerifier, error) {
	if trustedMaterial == nil {
		return nil, errors.New("trustedMaterial must not be nil")
	}
	v := &IdentityVerifier{trustedMaterial: trustedMaterial}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Verify verifies a VerifiableEntity's transparency log inclusion proof, checkpoint,
// and either its public key signature or OIDC identity claims against the provided policy.
func (v *IdentityVerifier) Verify(entity VerifiableEntity, pb PolicyBuilder) (*IdentityVerificationResult, error) {
	if entity == nil {
		return nil, errors.New("entity must not be nil")
	}
	tlogProofPB, err := entity.TransparencyLogProof()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transparency log proof: %w", err)
	}
	if tlogProofPB == nil || len(tlogProofPB.Proof) == 0 {
		return nil, errors.New("no transparency log proof found")
	}

	var tlogProof proof.TLogProof
	if err := tlogProof.Unmarshal(tlogProofPB.Proof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tlog proof: %w", err)
	}

	policy, err := pb.BuildConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build policy: %w", err)
	}

	artifactDigest, envelope, err := extractIdentityArtifactDigest(entity, policy)
	if err != nil {
		return nil, err
	}

	// Signature is nil when signing with an OIDC identity token.
	artifactSig, err := entity.Signature()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature: %w", err)
	}

	parsedCheckpoint, allTimestamps, err := verifyIdentityCheckpoint(&tlogProof, v.trustedMaterial)
	if err != nil {
		return nil, err
	}

	extraClaims, err := parseExtraData(tlogProof.ExtraData)
	if err != nil {
		return nil, err
	}

	// Artifact double hash
	msgHash := sha256.Sum256(artifactDigest)

	var contextHashes []byte
	var rootOfTrustHash [32]byte
	var receiptDigest [32]byte
	var verifiedIdentity *CertificateIdentity

	if len(artifactSig) > 0 {
		if policy.RequireIdentities() {
			return nil, errors.New("can't verify certificate identities: entity was signed with a public key")
		}

		receiptDigest = sha256.Sum256(artifactSig)

		var contextBytes []byte
		contextBytes, contextHashes, err = computeContextClaimHashes(extraClaims)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(contextBytes, policy.context) {
			return nil, errors.New("context in tlog extra data does not match policy context")
		}

		// c2sp.org/identity-transparency/v1 || 0x00 || SHA256(messageDigest) [|| contextHashes]
		prehashedData := append([]byte("c2sp.org/identity-transparency/v1\x00"), msgHash[:]...)
		prehashedData = append(prehashedData, contextHashes...)

		rootOfTrustHash, err = verifyPublicKeySignature(v.trustedMaterial, artifactSig, prehashedData, allTimestamps)
		if err != nil {
			return nil, err
		}
	} else {
		// OIDC Credential
		if policy.RequireSigningKey() {
			return nil, errors.New("expected key signature, not OIDC identity")
		}
		if len(policy.context) > 0 {
			return nil, errors.New("can't verify context: entity was not signed with a public key")
		}

		contextHashes = computeOIDCClaimHashes(extraClaims)

		issuer, ok := extraClaims["issuer"]
		if !ok || issuer == "" {
			return nil, errors.New("missing issuer in tlog extra claims for OIDC credential")
		}
		identity, ok := extraClaims["identity"]
		if !ok || identity == "" {
			return nil, errors.New("missing identity in tlog extra claims for OIDC credential")
		}

		if policy.RequireIdentities() {
			if len(policy.certificateIdentities) == 0 {
				return nil, errors.New("can't verify identities: no identities provided in policy")
			}

			summary := summarizeExtraClaims(extraClaims)

			verifiedIdentity, err = policy.certificateIdentities.Verify(summary)
			if err != nil {
				return nil, fmt.Errorf("failed to verify identity against policy: %w", err)
			}
		}

		rootOfTrustHash = sha256.Sum256([]byte(issuer))
	}

	if err := verifyIdentityInclusionProof(&tlogProof, parsedCheckpoint, rootOfTrustHash, msgHash, contextHashes, receiptDigest); err != nil {
		return nil, err
	}

	var statement *in_toto.Statement
	if envelope != nil {
		statement, err = verifyDSSEEnvelopeStatement(envelope, policy)
		if err != nil {
			return nil, err
		}
	}

	return &IdentityVerificationResult{
		Verified:         true,
		Timestamps:       allTimestamps,
		Statement:        statement,
		VerifiedIdentity: verifiedIdentity,
	}, nil
}

// summarizeExtraClaims maps the logged OIDC claims in extraClaims into a
// certificate.Summary so CertificateIdentity policies can require identity and
// issuer along with any subset of optional extension claims.
func summarizeExtraClaims(extraClaims map[string]string) certificate.Summary {
	return certificate.Summary{
		SubjectAlternativeName:              extraClaims["identity"],
		Issuer:                              extraClaims["issuer"],
		BuildSignerURI:                      extraClaims["build-signer-uri"],
		BuildSignerDigest:                   extraClaims["build-signer-digest"],
		RunnerEnvironment:                   extraClaims["runner-environment"],
		SourceRepositoryURI:                 extraClaims["source-repository-uri"],
		SourceRepositoryDigest:              extraClaims["source-repository-digest"],
		SourceRepositoryRef:                 extraClaims["source-repository-ref"],
		SourceRepositoryIdentifier:          extraClaims["source-repository-identifier"],
		SourceRepositoryOwnerURI:            extraClaims["source-repository-owner-uri"],
		SourceRepositoryOwnerIdentifier:     extraClaims["source-repository-owner-identifier"],
		BuildConfigURI:                      extraClaims["build-config-uri"],
		BuildConfigDigest:                   extraClaims["build-config-digest"],
		BuildTrigger:                        extraClaims["build-trigger"],
		RunInvocationURI:                    extraClaims["run-invocation-uri"],
		SourceRepositoryVisibilityAtSigning: extraClaims["source-repository-visibility-at-signing"],
	}
}

// extractIdentityArtifactDigest extracts the 32-byte SHA-256 artifact digest
// (or DSSE PAE digest) and optional EnvelopeContent from a VerifiableEntity
// according to the provided PolicyConfig.
func extractIdentityArtifactDigest(entity VerifiableEntity, policy *PolicyConfig) ([]byte, EnvelopeContent, error) {
	if entity.HasEnvelope() {
		if policy.RequireArtifact() && !policy.verifyArtifacts && !policy.verifyArtifactDigests {
			return nil, nil, errors.New("no artifact or artifact digest provided")
		}

		envelope, err := entity.Envelope()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch envelope: %w", err)
		}

		rawEnv := envelope.RawEnvelope()
		if rawEnv == nil {
			return nil, nil, errors.New("missing raw DSSE envelope")
		}
		payload, err := base64.StdEncoding.DecodeString(rawEnv.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
		}
		pae := dsse.PAE(rawEnv.PayloadType, payload)
		h := sha256.Sum256(pae)
		return h[:], envelope, nil
	}

	if !policy.RequireArtifact() {
		return nil, nil, errors.New("IdentityVerifier requires an artifact or artifact digest to be provided")
	}

	switch {
	case policy.verifyArtifacts:
		if len(policy.artifacts) != 1 || policy.artifacts[0] == nil {
			return nil, nil, errors.New("IdentityVerifier requires exactly one artifact")
		}
		hasher := sha256.New()
		if _, err := io.Copy(hasher, policy.artifacts[0]); err != nil {
			return nil, nil, fmt.Errorf("failed to hash artifact: %w", err)
		}
		return hasher.Sum(nil), nil, nil
	case policy.verifyArtifactDigests:
		if len(policy.artifactDigests) != 1 {
			return nil, nil, errors.New("IdentityVerifier requires exactly one artifact digest")
		}
		if strings.ToLower(policy.artifactDigests[0].Algorithm) != "sha256" {
			return nil, nil, fmt.Errorf("IdentityVerifier requires sha256 artifact digest algorithm, got %s", policy.artifactDigests[0].Algorithm)
		}
		if len(policy.artifactDigests[0].Digest) != sha256.Size {
			return nil, nil, fmt.Errorf("IdentityVerifier requires a %d-byte sha256 artifact digest, got %d bytes", sha256.Size, len(policy.artifactDigests[0].Digest))
		}
		return policy.artifactDigests[0].Digest, nil, nil
	default:
		return nil, nil, errors.New("no artifact or artifact digest provided")
	}
}

func verifyDSSEEnvelopeStatement(envelope EnvelopeContent, policy *PolicyConfig) (*in_toto.Statement, error) {
	if policy.RequireArtifact() {
		switch {
		case policy.verifyArtifacts:
			if err := verifyStatementWithArtifacts(envelope, policy.artifacts); err != nil {
				return nil, err
			}
		case policy.verifyArtifactDigests:
			if err := verifyStatementWithArtifactDigests(envelope, policy.artifactDigests); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("no artifact or artifact digest provided")
		}
	}

	stmt, err := envelope.Statement()
	if err != nil {
		return nil, fmt.Errorf("failed to extract statement from envelope: %w", err)
	}
	return stmt, nil
}

// verifyPublicKeySignature verifies an artifact signature against the trusted public keys in
// TrustedMaterial that are valid at all provided timestamps, returning the root-of-trust hash.
func verifyPublicKeySignature(tm root.TrustedMaterial, artifactSig, prehashedData []byte, timestamps []time.Time) ([32]byte, error) {
	for _, verifier := range tm.PublicKeyVerifiers() {
		validAtAll := true
		for _, ts := range timestamps {
			if !verifier.ValidAtTime(ts) {
				validAtAll = false
				break
			}
		}
		if !validAtAll {
			continue
		}

		pubKey, err := verifier.PublicKey()
		if err != nil {
			continue
		}
		mldsaKey, ok := pubKey.(*mldsa.PublicKey)
		if !ok || mldsaKey.Parameters() != mldsa.MLDSA44() {
			continue
		}

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			continue
		}

		if err := verifier.VerifySignature(bytes.NewReader(artifactSig), bytes.NewReader(prehashedData)); err != nil {
			continue
		}

		rot := append([]byte("ML-DSA-44"), pubKeyBytes...)
		return sha256.Sum256(rot), nil
	}

	return [32]byte{}, errors.New("artifact signature verification failed: no matching trusted public key")
}

// PKIVerifier verifies PKI-based signatures backed by a certificate authority and
// RFC 3161 timestamp authority without a transparency log.
type PKIVerifier struct {
	trustedMaterial          root.TrustedMaterial
	signedTimestampThreshold int
}

// PKIVerifierOption configures a PKIVerifier.
type PKIVerifierOption func(*PKIVerifier) error

// WithPKISignedTimestamps configures PKIVerifier to require at least threshold
// RFC 3161 signed timestamps. Defaults to 1 if not specified.
func WithPKISignedTimestamps(threshold int) PKIVerifierOption {
	return func(v *PKIVerifier) error {
		if threshold < 1 {
			return errors.New("signed timestamp threshold must be at least 1")
		}
		v.signedTimestampThreshold = threshold
		return nil
	}
}

// NewPKIVerifier creates a new PKIVerifier backed by the provided TrustedMaterial.
func NewPKIVerifier(trustedMaterial root.TrustedMaterial, options ...PKIVerifierOption) (*PKIVerifier, error) {
	if trustedMaterial == nil {
		return nil, errors.New("trustedMaterial must not be nil")
	}
	v := &PKIVerifier{
		trustedMaterial:          trustedMaterial,
		signedTimestampThreshold: 1,
	}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Verify verifies a PKI-signed VerifiableEntity against the provided policy.
func (v *PKIVerifier) Verify(_ VerifiableEntity, _ PolicyBuilder) (*IdentityVerificationResult, error) {
	// TODO: Implement PKI verification by:
	// 1. Extracting the artifact/DSSE digest and optional in-toto statement via extractIdentityArtifactDigest.
	// 2. Verifying RFC 3161 signed timestamps against v.trustedMaterial.TimestampingAuthorities()
	//    with v.signedTimestampThreshold via VerifySignedTimestampWithThreshold.
	// 3. Verifying the leaf certificate chain against v.trustedMaterial.FulcioCertificateAuthorities()
	//    at each verified timestamp via verifyLeafCertificate.
	// 4. Summarizing the leaf certificate via certificate.SummarizeCertificate and verifying
	//    certificate identities via policy.certificateIdentities.Verify.
	// 5. Verifying the artifact signature against the leaf certificate's public key.
	return nil, errNotImplemented
}

// KeyVerifier verifies managed key signatures without a transparency log, with
// optional RFC 3161 timestamp verification.
type KeyVerifier struct {
	trustedMaterial          root.TrustedMaterial
	signedTimestampThreshold int
}

// KeyVerifierOption configures a KeyVerifier.
type KeyVerifierOption func(*KeyVerifier) error

// WithKeySignedTimestamps configures KeyVerifier to require at least threshold
// RFC 3161 signed timestamps and verify that the signing key was valid at those timestamps.
func WithKeySignedTimestamps(threshold int) KeyVerifierOption {
	return func(v *KeyVerifier) error {
		if threshold < 1 {
			return errors.New("signed timestamp threshold must be at least 1")
		}
		v.signedTimestampThreshold = threshold
		return nil
	}
}

// NewKeyVerifier creates a new KeyVerifier backed by the provided TrustedMaterial.
func NewKeyVerifier(trustedMaterial root.TrustedMaterial, options ...KeyVerifierOption) (*KeyVerifier, error) {
	if trustedMaterial == nil {
		return nil, errors.New("trustedMaterial must not be nil")
	}
	v := &KeyVerifier{trustedMaterial: trustedMaterial}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Verify verifies a managed-key-signed VerifiableEntity against the provided policy.
func (v *KeyVerifier) Verify(_ VerifiableEntity, _ PolicyBuilder) (*IdentityVerificationResult, error) {
	// TODO: Implement managed key verification by:
	// 1. Extracting the artifact/DSSE digest and optional in-toto statement via extractIdentityArtifactDigest.
	// 2. When v.signedTimestampThreshold > 0, verifying RFC 3161 signed timestamps against
	//    v.trustedMaterial.TimestampingAuthorities() via VerifySignedTimestampWithThreshold.
	// 3. Verifying the artifact signature against v.trustedMaterial.PublicKeyVerifiers()
	//    valid at the verified timestamps via verifyPublicKeySignature.
	return nil, errNotImplemented
}
