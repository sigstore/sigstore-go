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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

type Signer interface {
	Sign(content Content, k Keypair) (*protobundle.Bundle, error)
}

type Fulcio struct {
	options *FulcioOptions
}

type FulcioOptions struct {
	// URL of Fulcio instance
	BaseURL string
	// OIDC token to send to Fulcio instance
	IdentityToken string
	// Optional timeout for network requests
	Timeout time.Duration
	// Optional version string for user agent
	LibraryVersion string
}

func NewFulcio(opts *FulcioOptions) *Fulcio {
	return &Fulcio{options: opts}
}

type jsonWebToken struct {
	Sub string `json:"sub"`
}

type fulcioCertRequest struct {
	PublicKeyRequest publicKeyRequest `json:"publicKeyRequest"`
}

type publicKeyRequest struct {
	PublicKey         publicKey `json:"publicKey"`
	ProofOfPossession string    `json:"proofOfPossession"`
}

type publicKey struct {
	Algorithm string `json:"algorithm"`
	Content   string `json:"content"`
}

type fulcioResponse struct {
	SctCertWithChain signedCertificateEmbeddedSct `json:"signedCertificateEmbeddedSct"`
}

type signedCertificateEmbeddedSct struct {
	Chain chain `json:"chain"`
}

type chain struct {
	Certificates []string `json:"certificates"`
}

func (f *Fulcio) Sign(content Content, keypair Keypair) (*protobundle.Bundle, error) {
	// See if keypair was provided
	if keypair == nil {
		var err error
		ephemeralKeypair, err := NewEphemeralKeypair(nil)
		if err != nil {
			return nil, err
		}
		keypair = ephemeralKeypair
	}

	// Get JWT from identity token
	//
	// Note that the contents of this token are untrusted. Fulcio will perform
	// the token verification.
	tokenParts := strings.Split(f.options.IdentityToken, ".")
	if len(tokenParts) < 2 {
		return nil, errors.New("Unable to get subject from identity token")
	}

	jwtString, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, err
	}

	var jwt jsonWebToken
	err = json.Unmarshal([]byte(jwtString), &jwt)
	if err != nil {
		return nil, err
	}

	// Sign JWT subject for proof of possession
	subjectSignature, err := keypair.SignData([]byte(jwt.Sub))
	if err != nil {
		return nil, err
	}

	// Make Fulcio certificate request
	keypairPem, err := keypair.GetPublicKeyPem()
	if err != nil {
		return nil, err
	}

	certRequest := fulcioCertRequest{
		PublicKeyRequest: publicKeyRequest{
			PublicKey: publicKey{
				Algorithm: keypair.GetKeyAlgorithm(),
				Content:   keypairPem,
			},
			ProofOfPossession: base64.StdEncoding.EncodeToString(subjectSignature),
		},
	}

	requestJSON, err := json.Marshal(&certRequest)
	if err != nil {
		return nil, err
	}
	requestBytes := bytes.NewBuffer(requestJSON)

	// TODO: For now we are using our own HTTP client
	//
	// https://github.com/sigstore/fulcio/pkg/api's client could be used in the
	// future, when it supports the v2 API
	var client http.Client
	if f.options.Timeout != 0 {
		client.Timeout = f.options.Timeout
	}

	request, err := http.NewRequest("POST", f.options.BaseURL+"/api/v2/signingCert", requestBytes)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", "Bearer "+f.options.IdentityToken)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("User-Agent", constructUserAgent(f.options.LibraryVersion))

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Fulcio returned %d: %s", response.StatusCode, string(body))
	}

	// Assemble bundle from Fulcio response
	var fulcioResp fulcioResponse
	err = json.Unmarshal(body, &fulcioResp)
	if err != nil {
		return nil, err
	}

	certs := fulcioResp.SctCertWithChain.Chain.Certificates
	if len(certs) == 0 {
		return nil, errors.New("Fulcio returned no certificates")
	}

	certBlock, _ := pem.Decode([]byte(certs[0]))
	if certBlock == nil {
		return nil, errors.New("unable to parse Fulcio certificate")
	}

	digest, err := content.GetDigest(keypair.GetHashAlgorithm())
	if err != nil {
		return nil, err
	}

	signature, err := keypair.SignData(digest)
	if err != nil {
		return nil, err
	}

	bundle := &protobundle.Bundle{
		MediaType: bundleV03MediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: certBlock.Bytes,
				},
			},
		},
	}

	content.Bundle(bundle, signature)

	return bundle, nil
}

type KeySigner struct{}

func (ks *KeySigner) Sign(content Content, keypair Keypair) (*protobundle.Bundle, error) {
	digest, err := content.GetDigest(keypair.GetHashAlgorithm())
	if err != nil {
		return nil, err
	}

	signature, err := keypair.SignData(digest)
	if err != nil {
		return nil, err
	}

	bundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: string(keypair.GetHint()),
				},
			},
		},
	}

	content.Bundle(bundle, signature)

	return bundle, nil
}
