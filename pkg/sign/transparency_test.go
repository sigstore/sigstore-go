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

package sign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/stretchr/testify/assert"
)

var envelopeBody []byte

type mockRekor struct{}

func (m *mockRekor) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	virtualSigstoreOnce.Do(setupVirtualSigstore)
	if virtualSigstoreErr != nil {
		return nil, virtualSigstoreErr
	}

	leafCert, leafPrivKey, err := virtualSigstore.GenerateLeafCert("identity", "issuer")
	if err != nil {
		return nil, err
	}

	signer, err := signature.LoadECDSASignerVerifier(leafPrivKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	dsseSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: signer,
		Pub:             leafCert.PublicKey.(*ecdsa.PublicKey),
	})
	if err != nil {
		return nil, err
	}

	envelope, err := dsseSigner.SignPayload(context.TODO(), "application/vnd.in-toto+json", envelopeBody)
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}

	entry, err := virtualSigstore.GenerateTlogEntry(leafCert, envelope, signature, time.Now().Unix())
	if err != nil {
		return nil, err
	}

	integratedTime := entry.IntegratedTime().Unix()
	logID := hex.EncodeToString([]byte(entry.LogKeyID()))
	logIndex := entry.LogIndex()
	rootHash := "deadbeef"
	treeSize := int64(1)
	payload := map[string]models.LogEntryAnon{
		"asdf": {
			Body:           entry.Body(),
			IntegratedTime: &integratedTime,
			LogID:          &logID,
			LogIndex:       &logIndex,
			Verification: &models.LogEntryAnonVerification{
				InclusionProof: &models.InclusionProof{
					Checkpoint: &rootHash,
					Hashes:     []string{},
					LogIndex:   &logIndex,
					RootHash:   &rootHash,
					TreeSize:   &treeSize,
				},
			},
		},
	}

	created := &entries.CreateLogEntryCreated{ETag: "asdf", Payload: payload}
	return created, nil
}

func Test_GetTransparencyLogEntry(t *testing.T) {
	// First create a bundle with DSSE content
	keypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)

	bundle := &protobundle.Bundle{MediaType: bundleV03MediaType}
	content := DSSEData{Data: []byte("hello world"), PayloadType: "something"}
	envelopeBody = content.PreAuthEncoding()
	signature, digest, err := keypair.SignData(content.PreAuthEncoding())
	assert.Nil(t, err)

	content.Bundle(bundle, signature, digest, keypair.GetHashAlgorithm())
	bundle.VerificationMaterial = &protobundle.VerificationMaterial{}

	// Test the happy path
	opts := &RekorOptions{Retries: 1, Client: &mockRekor{}}
	rekor := NewRekor(opts)
	pubkey, err := keypair.GetPublicKeyPem()
	assert.Nil(t, err)

	err = rekor.GetTransparencyLogEntry([]byte(pubkey), bundle)
	assert.Nil(t, err)
	assert.NotNil(t, bundle.VerificationMaterial.TlogEntries)
}
