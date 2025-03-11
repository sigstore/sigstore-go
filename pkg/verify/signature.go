// Copyright 2023 The Sigstore Authors.
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
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const maxAllowedSubjects = 1024
const maxAllowedSubjectDigests = 32

var ErrDSSEInvalidSignatureCount = errors.New("exactly one signature is required")

func VerifySignature(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelope(verifier, envelope)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return errors.New("artifact must be provided to verify message signature")
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content has neither an envelope or a message")
}

func VerifySignatureWithArtifact(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifact io.Reader) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifact(verifier, envelope, artifact)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignature(verifier, msg, artifact)
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content has neither an envelope or a message")
}

func VerifySignatureWithArtifacts(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifacts []io.Reader) error { // nolint: revive
	verifier, err := getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifacts(verifier, envelope, artifacts)
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content does not have an envelope")
}

func VerifySignatureWithArtifactDigest(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifactDigest []byte, artifactDigestAlgorithm string) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifactDigest(verifier, envelope, artifactDigest, artifactDigestAlgorithm)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignatureWithArtifactDigest(verifier, msg, artifactDigest)
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content has neither an envelope or a message")
}

func VerifySignatureWithArtifactDigests(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, digests []ArtifactDigest) error { // nolint: revive
	verifier, err := getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifactDigests(verifier, envelope, digests)
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content does not have an envelope")
}

func getSignatureVerifier(verificationContent VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert := verificationContent.Certificate(); leafCert != nil {
		// TODO: Inspect certificate's SignatureAlgorithm to determine hash function
		return signature.LoadVerifier(leafCert.PublicKey, crypto.SHA256)
	} else if pk := verificationContent.PublicKey(); pk != nil {
		return tm.PublicKeyVerifier(pk.Hint())
	}

	return nil, fmt.Errorf("no public key or certificate found")
}

func verifyEnvelope(verifier signature.Verifier, envelope EnvelopeContent) error {
	dsseEnv := envelope.RawEnvelope()

	// A DSSE envelope in a Sigstore bundle MUST only contain one
	// signature, even though DSSE is more permissive.
	if len(dsseEnv.Signatures) != 1 {
		return ErrDSSEInvalidSignatureCount
	}
	pub, err := verifier.PublicKey()
	if err != nil {
		return fmt.Errorf("could not fetch verifier public key: %w", err)
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
	})

	if err != nil {
		return fmt.Errorf("could not load envelope verifier: %w", err)
	}

	_, err = envVerifier.Verify(context.TODO(), dsseEnv)
	if err != nil {
		return fmt.Errorf("could not verify envelope: %w", err)
	}

	return nil
}

func verifyEnvelopeWithArtifact(verifier signature.Verifier, envelope EnvelopeContent, artifact io.Reader) error {
	artifacts := []io.Reader{artifact}
	return verifyEnvelopeWithArtifacts(verifier, envelope, artifacts)
}

func verifyEnvelopeWithArtifacts(verifier signature.Verifier, envelope EnvelopeContent, artifacts []io.Reader) error {
	if err := verifyEnvelope(verifier, envelope); err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	if err = limitSubjects(statement); err != nil {
		return err
	}
	// Sanity check (no subjects)
	if len(statement.Subject) == 0 {
		return errors.New("no subjects found in statement")
	}

	// determine which hash functions to use
	hashFuncs, err := getHashFunctions(statement)
	if err != nil {
		return fmt.Errorf("unable to determine hash functions: %w", err)
	}

	hashedArtifacts := make([]map[crypto.Hash][]byte, len(artifacts))
	for i, artifact := range artifacts {
		// Compute digest of the artifact.
		hasher, err := newMultihasher(hashFuncs)
		if err != nil {
			return fmt.Errorf("could not verify artifact: unable to create hasher: %w", err)
		}
		if _, err = io.Copy(hasher, artifact); err != nil {
			return fmt.Errorf("could not verify artifact: unable to calculate digest: %w", err)
		}
		hashedArtifacts[i] = hasher.Sum(nil)
	}

	// create a map based on the digests present in the statement
	// the map key is the hash algorithm and the field is a slice of digests
	// created using that hash algorithm
	subjectDigests := make(map[crypto.Hash][][]byte)
	for _, subject := range statement.Subject {
		for alg, hexdigest := range subject.Digest {
			hf, err := algStringToHashFunc(alg)
			if err != nil {
				continue
			}
			if _, ok := subjectDigests[hf]; !ok {
				subjectDigests[hf] = make([][]byte, 0)
			}
			digest, err := hex.DecodeString(hexdigest)
			if err != nil {
				continue
			}
			subjectDigests[hf] = append(subjectDigests[hf], digest)
		}
	}

	// now loop over the provided artifact digests and try to compare them
	// to the mapped subject digests
	// if we cannot find a match, exit with an error
	for _, ha := range hashedArtifacts {
		matchFound := false
		for key, value := range ha {
			statementDigests, ok := subjectDigests[key]
			if !ok {
				return fmt.Errorf("no matching artifact hash algorithm found in subject digests")
			}
			if ok := isDigestInSlice(value, statementDigests); ok {
				matchFound = true
				break
			}
		}
		if !matchFound {
			return fmt.Errorf("provided artifact digests do not match digests in statement")
		}
	}

	return nil
}

func verifyEnvelopeWithArtifactDigest(verifier signature.Verifier, envelope EnvelopeContent, artifactDigest []byte, artifactDigestAlgorithm string) error {
	ad := ArtifactDigest{
		Algorithm: artifactDigestAlgorithm,
		Digest:    artifactDigest,
	}
	artifactDigests := []ArtifactDigest{ad}
	return verifyEnvelopeWithArtifactDigests(verifier, envelope, artifactDigests)
}

func verifyEnvelopeWithArtifactDigests(verifier signature.Verifier, envelope EnvelopeContent, digests []ArtifactDigest) error {
	if err := verifyEnvelope(verifier, envelope); err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	if err = limitSubjects(statement); err != nil {
		return err
	}

	// create a map based on the digests present in the statement
	// the map key is the hash algorithm and the field is a slice of digests
	// created using that hash algorithm
	subjectDigests := make(map[string][][]byte)
	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			if _, ok := subjectDigests[alg]; !ok {
				subjectDigests[alg] = make([][]byte, 0)
			}
			hexdigest, err := hex.DecodeString(digest)
			if err != nil {
				return fmt.Errorf("could not verify artifact: unable to decode subject digest: %w", err)
			}
			subjectDigests[alg] = append(subjectDigests[alg], hexdigest)
		}
	}

	// now loop over the provided artifact digests and compare them to the mapped subject digests
	// if we cannot find a match, exit with an error
	for _, artifactDigest := range digests {
		statementDigests, ok := subjectDigests[artifactDigest.Algorithm]
		if !ok {
			return fmt.Errorf("provided artifact digests does not match digests in statement")
		}
		if ok := isDigestInSlice(artifactDigest.Digest, statementDigests); !ok {
			return fmt.Errorf("provided artifact digest does not match any digest in statement")
		}
	}

	return nil
}

func isDigestInSlice(digest []byte, digestSlice [][]byte) bool {
	for _, el := range digestSlice {
		if bytes.Equal(digest, el) {
			return true
		}
	}
	return false
}

func verifyMessageSignature(verifier signature.Verifier, msg MessageSignatureContent, artifact io.Reader) error {
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), artifact)
	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}

func verifyMessageSignatureWithArtifactDigest(verifier signature.Verifier, msg MessageSignatureContent, artifactDigest []byte) error {
	if !bytes.Equal(artifactDigest, msg.Digest()) {
		return errors.New("artifact does not match digest")
	}
	if _, ok := verifier.(*signature.ED25519Verifier); ok {
		return errors.New("message signatures with ed25519 signatures can only be verified with artifacts, and not just their digest")
	}
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), bytes.NewReader([]byte{}), options.WithDigest(artifactDigest))

	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}

// limitSubjects limits the number of subjects and digests in a statement to prevent DoS.
func limitSubjects(statement *in_toto.Statement) error {
	if len(statement.Subject) > maxAllowedSubjects {
		return fmt.Errorf("too many subjects: %d > %d", len(statement.Subject), maxAllowedSubjects)
	}
	for _, subject := range statement.Subject {
		// limit the number of digests too
		if len(subject.Digest) > maxAllowedSubjectDigests {
			return fmt.Errorf("too many digests: %d > %d", len(subject.Digest), maxAllowedSubjectDigests)
		}
	}
	return nil
}

type multihasher struct {
	hashfuncs []crypto.Hash
	hashes    []hash.Hash
}

func newMultihasher(hashfuncs []crypto.Hash) (*multihasher, error) {
	if len(hashfuncs) == 0 {
		return nil, errors.New("no hash functions specified")
	}
	hashes := make([]hash.Hash, len(hashfuncs))
	for i := range hashfuncs {
		hashes[i] = hashfuncs[i].New()
	}
	return &multihasher{
		hashfuncs: hashfuncs,
		hashes:    hashes,
	}, nil
}

func (m *multihasher) Write(p []byte) (n int, err error) {
	for i := range m.hashes {
		n, err = m.hashes[i].Write(p)
		if err != nil {
			return
		}
	}
	return
}

func (m *multihasher) Sum(b []byte) map[crypto.Hash][]byte {
	sums := make(map[crypto.Hash][]byte, len(m.hashes))
	for i := range m.hashes {
		sums[m.hashfuncs[i]] = m.hashes[i].Sum(b)
	}
	return sums
}

func algStringToHashFunc(alg string) (crypto.Hash, error) {
	switch alg {
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, errors.New("unsupported digest algorithm")
	}
}

// getHashFunctions returns the smallest subset of supported hash functions
// that are needed to verify all subjects in a statement.
func getHashFunctions(statement *in_toto.Statement) ([]crypto.Hash, error) {
	if len(statement.Subject) == 0 {
		return nil, errors.New("no subjects found in statement")
	}

	supportedHashFuncs := []crypto.Hash{crypto.SHA512, crypto.SHA384, crypto.SHA256}
	chosenHashFuncs := make([]crypto.Hash, 0, len(supportedHashFuncs))
	subjectHashFuncs := make([][]crypto.Hash, len(statement.Subject))

	// go through the statement and make a simple data structure to hold the
	// list of hash funcs for each subject (subjectHashFuncs)
	for i, subject := range statement.Subject {
		for alg := range subject.Digest {
			hf, err := algStringToHashFunc(alg)
			if err != nil {
				continue
			}
			subjectHashFuncs[i] = append(subjectHashFuncs[i], hf)
		}
	}

	// for each subject, see if we have chosen a compatible hash func, and if
	// not, add the first one that is supported
	for _, hfs := range subjectHashFuncs {
		// if any of the hash funcs are already in chosenHashFuncs, skip
		if len(intersection(hfs, chosenHashFuncs)) > 0 {
			continue
		}

		// check each supported hash func and add it if the subject
		// has a digest for it
		for _, hf := range supportedHashFuncs {
			if slices.Contains(hfs, hf) {
				chosenHashFuncs = append(chosenHashFuncs, hf)
				break
			}
		}
	}

	if len(chosenHashFuncs) == 0 {
		return nil, errors.New("no supported digest algorithms found")
	}

	return chosenHashFuncs, nil
}

func intersection(a, b []crypto.Hash) []crypto.Hash {
	var result []crypto.Hash
	for _, x := range a {
		if slices.Contains(b, x) {
			result = append(result, x)
		}
	}
	return result
}
