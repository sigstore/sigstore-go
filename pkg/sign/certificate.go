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
	"math"
	"net/http"
	"strings"
	"time"
)

type Fulcio struct {
	options *FulcioOptions
}

type FulcioOptions struct {
	// URL of Fulcio instance
	BaseURL string
	// Optional timeout for network requests
	Timeout time.Duration
	// Optional number of times to retry on HTTP 5XX
	Retries uint
	// Optional version string for user agent
	LibraryVersion string
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

func NewFulcio(opts *FulcioOptions) *Fulcio {
	return &Fulcio{options: opts}
}

// Returns DER-encoded code signing certificate
func (f *Fulcio) GetCertificate(keypair Keypair, identityToken string) ([]byte, error) {
	// Get JWT from identity token
	//
	// Note that the contents of this token are untrusted. Fulcio will perform
	// the token verification.
	tokenParts := strings.Split(identityToken, ".")
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
	subjectSignature, _, err := keypair.SignData([]byte(jwt.Sub))
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

	// TODO: For now we are using our own HTTP client
	//
	// https://github.com/sigstore/fulcio/pkg/api's client could be used in the
	// future, when it supports the v2 API
	var client http.Client
	if f.options.Timeout != 0 {
		client.Timeout = f.options.Timeout
	}

	attempts := uint(0)
	var response *http.Response

	for attempts <= f.options.Retries {
		request, err := http.NewRequest("POST", f.options.BaseURL+"/api/v2/signingCert", bytes.NewBuffer(requestJSON))
		if err != nil {
			return nil, err
		}
		request.Header.Add("Authorization", "Bearer "+identityToken)
		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("User-Agent", constructUserAgent(f.options.LibraryVersion))

		response, err = client.Do(request)
		if err != nil {
			return nil, err
		}

		if !(response.StatusCode >= 500 && response.StatusCode < 600) {
			// Not a HTTP 5XX error, don't retry
			break
		}

		attempts++
		delay := time.Duration(math.Pow(2, float64(attempts)))
		time.Sleep(delay * time.Second)
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

	return certBlock.Bytes, nil
}
