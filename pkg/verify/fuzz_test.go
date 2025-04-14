// Copyright 2024 The Sigstore Authors.
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

package verify_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

var FuzzSkipArtifactAndIdentitiesPolicy = verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithoutIdentitiesUnsafe())

/*
Tests VerifyTimestampAuthority with an entity that contains
a randomized email and statement
*/
func FuzzVerifyTimestampAuthorityWithoutThreshold(f *testing.F) {
	f.Fuzz(func(t *testing.T, email string, statement []byte) {
		virtualSigstore, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		entity, err := virtualSigstore.Attest(email,
			"issuer",
			statement)
		if err != nil {
			t.Skip()
		}
		//nolint:errcheck
		verify.VerifyTimestampAuthority(entity, virtualSigstore)
	})
}

/*
Tests VerifyTimestampAuthorityWithThreshold with an entity
that contains a randomized email, statement and a randomized
threshold
*/
func FuzzVerifyTimestampAuthorityWithThreshold(f *testing.F) {
	f.Fuzz(func(t *testing.T, email string,
		statement []byte,
		threshold int) {
		virtualSigstore, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		entity, err := virtualSigstore.Attest(email,
			"issuer",
			statement)
		if err != nil {
			t.Skip()
		}
		//nolint:errcheck
		verify.VerifyTimestampAuthorityWithThreshold(entity,
			virtualSigstore,
			threshold)
	})
}

/*
Tests VerifyArtifactTransparencyLog with an entity
that contains a randomized email and statement and
a randomized log threshold and integrated time
*/
func FuzzVerifyArtifactTransparencyLog(f *testing.F) {
	f.Fuzz(func(t *testing.T, email string,
		statement []byte,
		logThreshold int,
		trustIntegratedTime bool) {
		virtualSigstore, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		entity, err := virtualSigstore.Attest(email,
			"issuer",
			statement)
		if err != nil {
			t.Skip()
		}
		//nolint:errcheck
		verify.VerifyArtifactTransparencyLog(entity,
			virtualSigstore,
			logThreshold,
			trustIntegratedTime)
	})
}

/*
Tests Verify with an entity that contains a randomized
email and statement and a randomized root
*/
func FuzzSignedEntityVerifier(f *testing.F) {
	ctx := context.TODO()
	f.Fuzz(func(t *testing.T, trustedrootJSON,
		bundleBytes []byte) {
		trustedRoot, err := root.NewTrustedRootFromJSON(trustedrootJSON)
		if err != nil || trustedRoot == nil {
			t.Skip()
		}
		var b protobundle.Bundle
		err = protojson.Unmarshal(bundleBytes, &b)
		if err != nil {
			t.Skip()
		}
		entity, err := bundle.NewBundle(&b)
		if err != nil {
			t.Skip()
		}
		v, err := verify.NewSignedEntityVerifier(trustedRoot,
			verify.WithTransparencyLog(1),
			verify.WithObserverTimestamps(1))
		if err != nil {
			t.Fatal(err)
		}
		//nolint:errcheck
		v.Verify(ctx, entity, FuzzSkipArtifactAndIdentitiesPolicy)
	})
}

/*
Tests VerifySignature with a sigContent and verificationsContent
from an entity that contains a randomized email and statement.
*/
func FuzzVerifySignatureWithoutArtifactOrDigest(f *testing.F) {
	f.Fuzz(func(t *testing.T, email string, statement []byte) {
		virtualSigstore, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		entity, err := virtualSigstore.Attest(email, "issuer", statement)
		if err != nil {
			t.Skip()
		}
		sigContent, err := entity.SignatureContent()
		if err != nil {
			t.Fatal(err)
		}

		verificationContent, err := entity.VerificationContent()
		if err != nil {
			t.Fatal(err)
		}
		//nolint:errcheck
		verify.VerifySignature(sigContent, verificationContent, virtualSigstore)
	})
}

/*
Tests VerifySignatureWithArtifact with a sigContent and
verificationsContent from an entity that contains a randomized
email and statement. The fuzzer also creates an artifact from
random bytes
*/
func FuzzVerifySignatureWithArtifactWithoutDigest(f *testing.F) {
	f.Fuzz(func(t *testing.T, email string,
		statement,
		artifactBytes []byte) {
		virtualSigstore, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		entity, err := virtualSigstore.Attest(email, "issuer", statement)
		if err != nil {
			t.Skip()
		}
		sigContent, err := entity.SignatureContent()
		if err != nil {
			t.Fatal(err)
		}

		verificationContent, err := entity.VerificationContent()
		if err != nil {
			t.Fatal(err)
		}
		artifacts := []io.Reader{bytes.NewReader(artifactBytes)}
		//nolint:errcheck
		verify.VerifySignatureWithArtifacts(sigContent,
			verificationContent,
			virtualSigstore,
			artifacts)
	})
}

/*
Tests VerifySignatureWithArtifactDigest with a sigContent and
verificationsContent from an entity that contains a randomized
email and statement. The fuzzer also passes a digest from
random bytes and a random string for the algorithm
*/
func FuzzVerifySignatureWithArtifactDigest(f *testing.F) {
	f.Fuzz(func(t *testing.T, email,
		artifactDigestAlgorithm string,
		statement, artifactDigest []byte) {
		virtualSigstore, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		entity, err := virtualSigstore.Attest(email, "issuer", statement)
		if err != nil {
			t.Skip()
		}
		sigContent, err := entity.SignatureContent()
		if err != nil {
			t.Fatal(err)
		}

		verificationContent, err := entity.VerificationContent()
		if err != nil {
			t.Fatal(err)
		}
		artifactDigests := []verify.ArtifactDigest{{
			Algorithm: artifactDigestAlgorithm,
			Digest:    artifactDigest,
		}}
		//nolint:errcheck
		verify.VerifySignatureWithArtifactDigests(sigContent,
			verificationContent,
			virtualSigstore,
			artifactDigests)
	})
}
