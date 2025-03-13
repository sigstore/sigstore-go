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

func getSignatureVerifier(verificationContent VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert := verificationContent.Certificate(); leafCert != nil {
		// LoadDefaultSigner/Verifier functions accept a few options to select
		// the default signer/verifier when there are ambiguities, like for
		// ED25519 keys, which could be used with PureEd25519 or Ed25519ph.
		//
		// Pass `WithED25519ph()` to select Ed25519ph by default, when ED25519
		// key is found, because for hashedrekord entries this is the only option.
		return signature.LoadDefaultVerifier(leafCert.PublicKey, options.WithED25519ph())
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
	err := verifyEnvelope(verifier, envelope)
	if err != nil {
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

	// Compute digest of the artifact.
	hasher, err := newMultihasher(hashFuncs)
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to create hasher: %w", err)
	}
	_, err = io.Copy(hasher, artifact)
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to calculate digest: %w", err)
	}
	artifactDigests := hasher.Sum(nil)

	// Look for artifact digest in statement
	for _, subject := range statement.Subject {
		for alg, hexdigest := range subject.Digest {
			hf, err := algStringToHashFunc(alg)
			if err != nil {
				continue
			}
			if artifactDigest, ok := artifactDigests[hf]; ok {
				digest, err := hex.DecodeString(hexdigest)
				if err != nil {
					continue
				}
				if bytes.Equal(artifactDigest, digest) {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("could not verify artifact: unable to confirm artifact digest is present in subject digests: %w", err)
}

func verifyEnvelopeWithArtifactDigest(verifier signature.Verifier, envelope EnvelopeContent, artifactDigest []byte, artifactDigestAlgorithm string) error {
	err := verifyEnvelope(verifier, envelope)
	if err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	if err = limitSubjects(statement); err != nil {
		return err
	}

	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			if alg == artifactDigestAlgorithm {
				hexdigest, err := hex.DecodeString(digest)
				if err != nil {
					return fmt.Errorf("could not verify artifact: unable to decode subject digest: %w", err)
				}
				if bytes.Equal(hexdigest, artifactDigest) {
					return nil
				}
			}
		}
	}
	return errors.New("provided artifact digest does not match any digest in statement")
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
	io.Writer
	hashfuncs []crypto.Hash
	hashes    []io.Writer
}

func newMultihasher(hashfuncs []crypto.Hash) (*multihasher, error) {
	if len(hashfuncs) == 0 {
		return nil, errors.New("no hash functions specified")
	}
	hashes := make([]io.Writer, len(hashfuncs))
	for i := range hashfuncs {
		hashes[i] = hashfuncs[i].New()
	}
	return &multihasher{
		Writer:    io.MultiWriter(hashes...),
		hashfuncs: hashfuncs,
		hashes:    hashes,
	}, nil
}

func (m *multihasher) Sum(b []byte) map[crypto.Hash][]byte {
	sums := make(map[crypto.Hash][]byte, len(m.hashes))
	for i := range m.hashes {
		sums[m.hashfuncs[i]] = m.hashes[i].(hash.Hash).Sum(b)
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
