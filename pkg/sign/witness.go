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
	"bytes"
	"crypto"
	"crypto/sha256"
	"io"

	"github.com/digitorus/timestamp"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	tsaclient "github.com/sigstore/timestamp-authority/pkg/client"
	tsagenclient "github.com/sigstore/timestamp-authority/pkg/generated/client/timestamp"
)

type Witness interface {
	Witness(*protobundle.Bundle) error
}

type TimestampAuthority struct {
	baseURL string
}

func WitnessTimestampAuthority(baseURL string) TimestampAuthority {
	return TimestampAuthority{
		baseURL: baseURL,
	}
}

func (ta *TimestampAuthority) Witness(b *protobundle.Bundle) error {
	req := &timestamp.Request{
		Certificates: true,
	}

	messageSignature := b.GetMessageSignature()

	if messageSignature != nil {
		signatureHash := sha256.Sum256(messageSignature.Signature)
		req.HashAlgorithm = crypto.SHA256
		req.HashedMessage = signatureHash[:]
	}

	reqBytes, err := req.Marshal()
	if err != nil {
		return err
	}

	client, err := tsaclient.GetTimestampClient(ta.baseURL, tsaclient.WithUserAgent("sigstore-go"), tsaclient.WithContentType(tsaclient.TimestampQueryMediaType))
	if err != nil {
		return err
	}

	clientParams := tsagenclient.NewGetTimestampResponseParams()
	// TODO: call clientParams.SetTimeout()
	clientParams.Request = io.NopCloser(bytes.NewReader(reqBytes))

	var respBytes bytes.Buffer
	_, err = client.Timestamp.GetTimestampResponse(clientParams, &respBytes)
	if err != nil {
		return err
	}

	_, err = timestamp.ParseResponse(respBytes.Bytes())
	if err != nil {
		return err
	}

	signedTimestamp := &protocommon.RFC3161SignedTimestamp{
		SignedTimestamp: respBytes.Bytes(),
	}

	vm := b.GetVerificationMaterial()
	if vm == nil {
		vm = &protobundle.VerificationMaterial{}
		b.VerificationMaterial = vm
	}

	tsVerificationData := vm.GetTimestampVerificationData()
	if tsVerificationData == nil {
		tsVerificationData = &protobundle.TimestampVerificationData{}
		vm.TimestampVerificationData = tsVerificationData
	}

	tsVerificationData.Rfc3161Timestamps = append(tsVerificationData.Rfc3161Timestamps, signedTimestamp)

	return nil
}

// TODO: implement
// type Rekor struct {
//	baseURL   string
//	entryType string
// }

// func (r *Rekor) Witness(_ *protobundle.Bundle) error {
//	// hashedrekord uses signature and dataDigest
//	// dsse uses envelope and ephemeralPublicKey
//	return nil
// }
