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
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"filippo.io/mldsa"
	"golang.org/x/crypto/cryptobyte"

	mldsax509 "filippo.io/mldsa/x509"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	merkleproof "github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

type IdentityVerifier struct {
	trustedMaterial root.TrustedMaterial
}

type IdentityVerifierOption func(*IdentityVerifier) error

func NewIdentityVerifier(trustedMaterial root.TrustedMaterial, options ...IdentityVerifierOption) (*IdentityVerifier, error) {
	v := &IdentityVerifier{trustedMaterial: trustedMaterial}
	for _, opt := range options {
		if err := opt(v); err != nil {
			return nil, err
		}
	}
	return v, nil
}

type IdentityVerificationResult struct {
	Verified   bool
	Timestamps []time.Time
}

func (v *IdentityVerifier) Verify(entity SignedEntity, pb PolicyBuilder) (*IdentityVerificationResult, error) {
	proofs, err := entity.TlogProofs()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tlog proofs: %w", err)
	}
	if len(proofs) == 0 {
		return nil, errors.New("no tlog proofs found")
	}

	var artifactSig []byte
	// Signature is not present for signing with an identity token
	if sigContent, err := entity.SignatureContent(); err == nil && sigContent != nil {
		artifactSig = sigContent.Signature()
	}

	var tlogProof proof.TLogProof
	if err := tlogProof.Unmarshal(proofs[0].Proof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tlog proof: %w", err)
	}

	policy, err := pb.BuildConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build policy: %w", err)
	}

	if !policy.RequireArtifact() {
		return nil, errors.New("IdentityVerifier requires an artifact or artifact digest to be provided")
	}

	var artifactDigest []byte
	switch {
	case policy.verifyArtifacts:
		if len(policy.artifacts) != 1 {
			return nil, errors.New("IdentityVerifier requires exactly one artifact")
		}
		hasher := sha256.New()
		if _, err := io.Copy(hasher, policy.artifacts[0]); err != nil {
			return nil, fmt.Errorf("failed to hash artifact: %w", err)
		}
		artifactDigest = hasher.Sum(nil)
	case policy.verifyArtifactDigests:
		if len(policy.artifactDigests) != 1 {
			return nil, errors.New("IdentityVerifier requires exactly one artifact digest")
		}
		artifactDigest = policy.artifactDigests[0].Digest
	default:
		return nil, errors.New("no artifact or artifact digest provided")
	}

	// Parse Checkpoint
	// We extract the origin (first line) to find the correct log verifier.
	parts := bytes.Split(tlogProof.Checkpoint, []byte("\n"))
	if len(parts) < 3 {
		return nil, errors.New("invalid checkpoint format")
	}
	origin := string(parts[0])

	var size uint64
	var rootHash []byte
	var allTimestamps []time.Time
	checkpointVerified := false

	var verifyErrors []error
	// Iterate over the trustedMaterial RekorLogs to find one that can verify the checkpoint
	for _, rekorLog := range v.trustedMaterial.RekorLogs() {
		var verifier signature.Verifier
		switch pk := rekorLog.PublicKey.(type) {
		case *mldsa.PublicKey:
			verifier = &mldsaLogVerifier{pubKey: pk}
		default:
			v, err := getVerifier(rekorLog.PublicKey, rekorLog.SignatureHashFunc)
			if err != nil {
				verifyErrors = append(verifyErrors, fmt.Errorf("getVerifier failed: %w", err))
				continue
			}
			verifier = *v
		}

		parsedCheckpoint, timestamps, err := parseCheckpoint(tlogProof.Checkpoint, origin, verifier)
		if err != nil {
			verifyErrors = append(verifyErrors, fmt.Errorf("ParseCheckpoint failed: %w", err))
			continue
		}
		checkpointVerified = true
		size = parsedCheckpoint.Size
		rootHash = parsedCheckpoint.Hash
		allTimestamps = append(allTimestamps, timestamps...)
		break
	}

	if !checkpointVerified {
		return nil, fmt.Errorf("failed to verify checkpoint against any trusted log. Errors: %v", verifyErrors)
	}
	// Context hashes from ExtraData
	var extraClaims map[string]string
	if len(tlogProof.ExtraData) > 0 {
		extraClaims = make(map[string]string)
		lines := bytes.SplitSeq(tlogProof.ExtraData, []byte("\n"))
		for line := range lines {
			if len(line) == 0 {
				continue
			}
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				extraClaims[string(parts[0])] = string(parts[1])
			}
		}
	}

	var contextHashes []byte
	if len(extraClaims) > 0 {
		type kv struct {
			k, v string
			hk   []byte
		}
		var kvs []kv
		for k, val := range extraClaims {
			hk := sha256.Sum256([]byte(k))
			hk2 := sha256.Sum256(hk[:])
			kvs = append(kvs, kv{k, val, hk2[:]})
		}
		sort.Slice(kvs, func(i, j int) bool {
			return kvs[i].k < kvs[j].k
		})
		for _, pair := range kvs {
			hv := sha256.Sum256([]byte(pair.v))
			hv2 := sha256.Sum256(hv[:])
			contextHashes = append(contextHashes, pair.hk...)
			contextHashes = append(contextHashes, hv2[:]...)
		}
	}

	// Artifact double hash
	msgHash := sha256.Sum256(artifactDigest)

	var rootOfTrustHash [32]byte
	var receiptDigest [32]byte

	if len(artifactSig) > 0 {
		// Receipt Digest
		receiptDigest = sha256.Sum256(artifactSig)

		vc, err := entity.VerificationContent()
		if err != nil {
			return nil, err
		}
		pk := vc.PublicKey()
		if pk != nil {
			verifier, err := v.trustedMaterial.PublicKeyVerifier(pk.Hint())
			if err != nil {
				return nil, fmt.Errorf("failed to get public key verifier: %w", err)
			}

			pubKey, err := verifier.PublicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to get public key from verifier: %w", err)
			}

			pubKeyBytes, err := mldsax509.MarshalPKIXPublicKey(pubKey)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal public key: %w", err)
			}

			rot := append([]byte("ML-DSA-44"), pubKeyBytes...)
			rootOfTrustHash = sha256.Sum256(rot)

			// c2sp.org/identity-transparency/v1 || 0x00 || SHA256(messageDigest)
			doubleHash := sha256.Sum256(artifactDigest)
			prehashedData := append([]byte("c2sp.org/identity-transparency/v1\x00"), doubleHash[:]...)
			if err := verifier.VerifySignature(bytes.NewReader(artifactSig), bytes.NewReader(prehashedData)); err != nil {
				return nil, fmt.Errorf("artifact signature verification failed: %w", err)
			}
		} else {
			return nil, errors.New("only PublicKey is supported for now when signature is present")
		}
	} else {
		// OIDC Credential
		issuer, ok := extraClaims["issuer"]
		if !ok {
			return nil, errors.New("missing issuer in tlog extra claims for OIDC credential")
		}
		identity, ok := extraClaims["identity"]
		if !ok {
			return nil, errors.New("missing identity in tlog extra claims for OIDC credential")
		}

		if policy.RequireIdentities() {
			if len(policy.certificateIdentities) == 0 {
				return nil, errors.New("can't verify identities: no identities provided in policy")
			}

			summary := certificate.Summary{
				SubjectAlternativeName: identity,
				Extensions: certificate.Extensions{
					Issuer: issuer,
				},
			}

			_, err = policy.certificateIdentities.Verify(summary)
			if err != nil {
				return nil, fmt.Errorf("failed to verify identity against policy: %w", err)
			}
		}

		rootOfTrustHash = sha256.Sum256([]byte(issuer))
	}

	// Construct leaf_hash
	leafHash := []byte{0x01}
	leafHash = append(leafHash, rootOfTrustHash[:]...)
	leafHash = append(leafHash, msgHash[:]...)
	leafHash = append(leafHash, contextHashes...)
	leafHash = append(leafHash, receiptDigest[:]...)

	hasher := rfc6962.DefaultHasher
	computedLeafHash := hasher.HashLeaf(leafHash)

	proofHashes := make([][]byte, len(tlogProof.Hashes))
	for i, h := range tlogProof.Hashes {
		proofHashes[i] = h[:]
	}

	// Verify inclusion proof
	err = merkleproof.VerifyInclusion(hasher, tlogProof.Index, size, computedLeafHash, proofHashes, rootHash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify inclusion proof: %w", err)
	}

	return &IdentityVerificationResult{Verified: true, Timestamps: allTimestamps}, nil
}

func parseCheckpoint(chkpt []byte, origin string, verifier signature.Verifier) (*formatsLog.Checkpoint, []time.Time, error) {
	parts := bytes.SplitN(chkpt, []byte("\n\n\u2014 "), 2)
	if len(parts) < 2 {
		return nil, nil, errors.New("invalid note format: missing signature block")
	}

	msg := append(bytes.Clone(parts[0]), '\n')
	cp := &formatsLog.Checkpoint{}
	_, err := cp.Unmarshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal checkpoint: %w", err)
	}
	if cp.Origin != origin {
		return nil, nil, fmt.Errorf("got Origin %q but expected %q", cp.Origin, origin)
	}

	sigs := bytes.Split(parts[1], []byte("\n"))
	verified := false
	var verifiedTimestamps []time.Time
	for _, sigLine := range sigs {
		if len(sigLine) == 0 {
			continue
		}
		sigParts := bytes.Split(sigLine, []byte(" "))
		if len(sigParts) != 2 {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(string(sigParts[1]))
		if err != nil || len(sigBytes) < 5 {
			continue
		}
		// The first 4 bytes are the key hash, skip them
		rawSig := sigBytes[4:]
		msgToVerify := msg

		// If this is ML-DSA, we need to extract the 8-byte timestamp and format the message
		pk, _ := verifier.PublicKey()
		isMLDSA := false
		var t uint64
		if _, is := pk.(*mldsa.PublicKey); is {
			if len(rawSig) < 8 {
				continue
			}
			isMLDSA = true
			t = binary.BigEndian.Uint64(rawSig[:8])
			rawSig = rawSig[8:]

			builder := cryptobyte.NewBuilder(nil)
			builder.AddBytes([]byte("subtree/v1\n\x00"))
			builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddBytes([]byte(origin))
			})
			builder.AddUint64(t)
			builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddBytes([]byte(cp.Origin))
			})
			builder.AddUint64(0)
			builder.AddUint64(cp.Size)
			builder.AddBytes(cp.Hash)

			formattedMsg, err := builder.Bytes()
			if err != nil {
				continue
			}
			msgToVerify = formattedMsg
		}

		if err := verifier.VerifySignature(bytes.NewReader(rawSig), bytes.NewReader(msgToVerify)); err == nil {
			verified = true
			if isMLDSA {
				verifiedTimestamps = append(verifiedTimestamps, time.Unix(0, int64(t)))
			}
		}
	}

	if !verified {
		return nil, nil, errors.New("failed to verify signatures on checkpoint")
	}

	return cp, verifiedTimestamps, nil
}

type mldsaLogVerifier struct {
	pubKey *mldsa.PublicKey
}

func (m *mldsaLogVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.pubKey, nil
}

func (m *mldsaLogVerifier) VerifySignature(sig, message io.Reader, _ ...signature.VerifyOption) error {
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return err
	}
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(m.pubKey, msgBytes, sigBytes, nil); err != nil {
		return fmt.Errorf("ML-DSA signature verification failed: %w", err)
	}
	return nil
}
