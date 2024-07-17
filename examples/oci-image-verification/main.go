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

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

var artifact *string
var artifactDigest *string
var artifactDigestAlgorithm *string
var expectedOIDIssuer *string
var expectedSAN *string
var expectedSANRegex *string
var requireTimestamp *bool
var requireTlog *bool
var minBundleVersion *string
var onlineTlog *bool
var trustedPublicKey *string
var trustedrootJSONpath *string
var tufRootURL *string
var tufDirectory *string
var ociImage *string

func init() {
	artifact = flag.String("artifact", "", "Path to artifact to verify")
	artifactDigest = flag.String("artifact-digest", "", "Hex-encoded digest of artifact to verify")
	artifactDigestAlgorithm = flag.String("artifact-digest-algorithm", "sha256", "Digest algorithm")
	expectedOIDIssuer = flag.String("expectedIssuer", "", "The expected OIDC issuer for the signing certificate")
	expectedSAN = flag.String("expectedSAN", "", "The expected identity in the signing certificate's SAN extension")
	expectedSANRegex = flag.String("expectedSANRegex", "", "The expected identity in the signing certificate's SAN extension")
	requireTimestamp = flag.Bool("requireTimestamp", true, "Require either an RFC3161 signed timestamp or log entry integrated timestamp")
	requireTlog = flag.Bool("requireTlog", true, "Require Artifact Transparency log entry (Rekor)")
	minBundleVersion = flag.String("minBundleVersion", "", "Minimum acceptable bundle version (e.g. '0.1')")
	onlineTlog = flag.Bool("onlineTlog", false, "Verify Artifact Transparency log entry online (Rekor)")
	trustedPublicKey = flag.String("publicKey", "", "Path to trusted public key")
	trustedrootJSONpath = flag.String("trustedrootJSONpath", "examples/trusted-root-public-good.json", "Path to trustedroot JSON file")
	tufRootURL = flag.String("tufRootURL", "", "URL of TUF root containing trusted root JSON file")
	tufDirectory = flag.String("tufDirectory", "tufdata", "Directory to store TUF metadata")
	ociImage = flag.String("ociImage", "", "OCI image to verify")
	flag.Parse()
	if flag.NArg() == 0 && *ociImage == "" {
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] BUNDLE_FILE ...\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	if err := run(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	var b *bundle.ProtobufBundle
	var err error

	if *ociImage != "" {
		// Build a bundle from OCI image reference and get its digest
		b, artifactDigest, err = bundleFromOCIImage(*ociImage)
	} else {
		// Load the bundle from file
		b, err = bundle.LoadJSONFromPath(flag.Arg(0))
	}
	if err != nil {
		return err
	}
	if *minBundleVersion != "" {
		if !b.MinVersion(*minBundleVersion) {
			return fmt.Errorf("bundle is not of minimum version %s", *minBundleVersion)
		}
	}

	verifierConfig := []verify.VerifierOption{}
	identityPolicies := []verify.PolicyOption{}
	var artifactPolicy verify.ArtifactPolicyOption

	verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))

	if *requireTimestamp {
		verifierConfig = append(verifierConfig, verify.WithObserverTimestamps(1))
	}

	if *requireTlog {
		verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1))
	}

	if *onlineTlog {
		verifierConfig = append(verifierConfig, verify.WithOnlineVerification())
	}

	if *expectedOIDIssuer != "" || *expectedSAN != "" || *expectedSANRegex != "" {
		certID, err := verify.NewShortCertificateIdentity(*expectedOIDIssuer, *expectedSAN, *expectedSANRegex)
		if err != nil {
			return err
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certID))
	}

	var trustedMaterial = make(root.TrustedMaterialCollection, 0)
	var trustedRootJSON []byte

	if *tufRootURL != "" {
		opts := tuf.DefaultOptions()
		opts.RepositoryBaseURL = *tufRootURL
		client, err := tuf.New(opts)
		if err != nil {
			return err
		}
		trustedRootJSON, err = client.GetTarget("trusted_root.json")
		if err != nil {
			return err
		}
	} else if *trustedrootJSONpath != "" {
		trustedRootJSON, err = os.ReadFile(*trustedrootJSONpath)
	}
	if err != nil {
		return err
	}

	if len(trustedRootJSON) > 0 {
		var trustedRoot *root.TrustedRoot
		trustedRoot, err = root.NewTrustedRootFromJSON(trustedRootJSON)
		if err != nil {
			return err
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}
	if *trustedPublicKey != "" {
		pemBytes, err := os.ReadFile(*trustedPublicKey)
		if err != nil {
			return err
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return errors.New("failed to decode pem block")
		}
		pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return err
		}
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(pubKey))
	}

	if len(trustedMaterial) == 0 {
		return errors.New("no trusted material provided")
	}

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verifierConfig...)
	if err != nil {
		return err
	}

	if *artifactDigest != "" { //nolint:gocritic
		artifactDigestBytes, err := hex.DecodeString(*artifactDigest)
		if err != nil {
			return err
		}
		artifactPolicy = verify.WithArtifactDigest(*artifactDigestAlgorithm, artifactDigestBytes)
	} else if *artifact != "" {
		file, err := os.Open(*artifact)
		if err != nil {
			return err
		}
		artifactPolicy = verify.WithArtifact(file)
	} else {
		artifactPolicy = verify.WithoutArtifactUnsafe()
		fmt.Fprintf(os.Stderr, "No artifact provided, skipping artifact verification. This is unsafe!\n")
	}

	res, err := sev.Verify(b, verify.NewPolicy(artifactPolicy, identityPolicies...))
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Verification successful!\n")
	marshaled, err := json.MarshalIndent(res, "", "   ")
	if err != nil {
		return err
	}
	fmt.Println(string(marshaled))
	return nil
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}

// bundleFromOCIImage returns a ProtobufBundle based on OCI image reference.
func bundleFromOCIImage(imageRef string) (*bundle.ProtobufBundle, *string, error) {
	// 1. Get the simple signing layer
	simpleSigning, err := simpleSigningLayerFromOCIImage(imageRef)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting simple signing layer: %w", err)
	}
	// 2. Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(simpleSigning)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting verification material: %w", err)
	}
	// 3. Build the message signature for the bundle
	msgSignature, err := getBundleMsgSignature(simpleSigning)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting message signature: %w", err)
	}
	// 4. Construct and verify the bundle
	bundleMediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, nil, fmt.Errorf("error getting bundle media type: %w", err)
	}
	pb := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}
	bun, err := bundle.NewProtobufBundle(&pb)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating bundle: %w", err)
	}
	// 5. Return the bundle and the digest of the simple signing layer (this is what is signed)
	return bun, &simpleSigning.Digest.Hex, nil
}

// simpleSigningLayerFromOCIImage returns the simple signing layer from the OCI image reference
func simpleSigningLayerFromOCIImage(imageRef string) (*v1.Descriptor, error) {
	// 1. Get the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference: %w", err)
	}
	// 2. Get the image descriptor
	desc, err := remote.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("error getting image descriptor: %w", err)
	}
	// 3. Get the digest
	digest := ref.Context().Digest(desc.Digest.String())
	h, err := v1.NewHash(digest.Identifier())
	if err != nil {
		return nil, fmt.Errorf("error getting hash: %w", err)
	}
	// 4. Construct the signature reference - sha256-<hash>.sig
	sigTag := digest.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sig"))
	// 5. Get the manifest of the signature
	mf, err := crane.Manifest(sigTag.Name())
	if err != nil {
		return nil, fmt.Errorf("error getting signature manifest: %w", err)
	}
	sigManifest, err := v1.ParseManifest(bytes.NewReader(mf))
	if err != nil {
		return nil, fmt.Errorf("error parsing signature manifest: %w", err)
	}
	// 6. Ensure there is at least one layer and it is a simple signing layer
	if len(sigManifest.Layers) == 0 || sigManifest.Layers[0].MediaType != "application/vnd.dev.cosign.simplesigning.v1+json" {
		return nil, fmt.Errorf("no suitable layers found in signature manifest")
	}
	// 7. Return the layer - most probably there are more layers (one for each signature) but verifying one is enough
	return &sigManifest.Layers[0], nil
}

// getBundleVerificationMaterial returns the bundle verification material from the simple signing layer
func getBundleVerificationMaterial(manifestLayer *v1.Descriptor) (*protobundle.VerificationMaterial, error) {
	// 1. Get the signing certificate chain
	signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting signing certificate: %w", err)
	}
	// 2. Get the transparency log entries
	tlogEntries, err := getVerificationMaterialTlogEntries(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting tlog entries: %w", err)
	}
	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   signingCert,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: nil,
	}, nil
}

// getVerificationMaterialTlogEntries returns the verification material transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer *v1.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation
	bun := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	// 2. Get the log index, log ID, integrated time, signed entry timestamp and body
	logIndex, ok := jsonData["Payload"].(map[string]interface{})["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := jsonData["Payload"].(map[string]interface{})["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := jsonData["Payload"].(map[string]interface{})["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}
	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := jsonData["Payload"].(map[string]interface{})["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	apiVersion := jsonData["apiVersion"].(string)
	kind := jsonData["kind"].(string)
	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

// getVerificationMaterialX509CertificateChain returns the verification material X509 certificate chain from the simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer *v1.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations["dev.sigstore.cosign/certificate"]
	// 2. Construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple signing layer
func getBundleMsgSignature(simpleSigningLayer *v1.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch simpleSigningLayer.Digest.Algorithm {
	case "sha256":
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", simpleSigningLayer.Digest.Algorithm)
	}
	// 2. Get the message digest
	digest, err := hex.DecodeString(simpleSigningLayer.Digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("error decoding digest: %w", err)
	}
	// 3. Get the signature
	s := simpleSigningLayer.Annotations["dev.cosignproject.cosign/signature"]
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding manSig: %w", err)
	}
	// Construct the bundle message signature
	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: msgHashAlg,
				Digest:    digest,
			},
			Signature: sig,
		},
	}, nil
}
