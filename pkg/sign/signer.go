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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512" // if user chooses SHA2-384 or SHA2-512 for hash
	"crypto/x509"
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

type Signer interface {
	Sign(content Content) (*protobundle.Bundle, error)
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

func SignerFulcio(opts *FulcioOptions) *Fulcio {
	return &Fulcio{options: opts}
}

type jsonWebToken struct {
	Sub string `json:"sub"`
}

type fulcioCertRequest struct {
	Credentials      identityToken    `json:"credentials"`
	PublicKeyRequest publicKeyRequest `json:"publicKeyRequest"`
}

type identityToken struct {
	OIDCIdentityToken string `json:"oidcIdentityToken"`
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
	SCT signedCertificateEmbeddedSct `json:"signedCertificateEmbeddedSct"`
}

type signedCertificateEmbeddedSct struct {
	Chain chain `json:"chain"`
}

type chain struct {
	Certificates []string `json:"certificates"`
}

func (f *Fulcio) Sign(content Content) (*protobundle.Bundle, error) {
	// Get JWT from identity token
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

	// Generate ephemeral keypair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}

	pemBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	var pemBytes bytes.Buffer
	if err = pem.Encode(&pemBytes, &pemBlock); err != nil {
		return nil, err
	}

	// Sign JWT subject with ephemeral key for proof of possession
	subjectDigest := sha256.Sum256([]byte(jwt.Sub))
	subjectSignature, err := privateKey.Sign(rand.Reader, subjectDigest[:], nil)
	if err != nil {
		return nil, err
	}

	// Make Fulcio certificate request
	certRequest := fulcioCertRequest{
		Credentials: identityToken{
			OIDCIdentityToken: f.options.IdentityToken,
		},
		PublicKeyRequest: publicKeyRequest{
			PublicKey: publicKey{
				Algorithm: "ECDSA",
				Content:   pemBytes.String(),
			},
			ProofOfPossession: base64.StdEncoding.EncodeToString(subjectSignature),
		},
	}

	requestJSON, err := json.Marshal(&certRequest)
	if err != nil {
		return nil, err
	}
	requestBytes := bytes.NewBuffer(requestJSON)

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

	certs := fulcioResp.SCT.Chain.Certificates
	if len(certs) == 0 {
		return nil, errors.New("Fulcio returned no certificates")
	}

	certBlock, _ := pem.Decode([]byte(certs[0]))
	if certBlock == nil {
		return nil, errors.New("unable to parse Fulcio certificate")
	}

	data := content.Prepare()
	dataDigest := sha256.Sum256([]byte(data))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, dataDigest[:])
	if err != nil {
		return nil, err
	}

	bundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: certBlock.Bytes,
				},
			},
		},
	}

	content.Bundle(bundle, protocommon.HashAlgorithm_SHA2_256, dataDigest[:], signature)

	return bundle, nil
}

type Keypair struct {
	options *KeypairOptions
}

type KeypairOptions struct {
	// Object that supports crypto.Signer.Sign, like crypto.PrivateKey
	Signer crypto.Signer
	// Hash algorithm to use to create digest of data provided to sign
	HashAlgorithm protocommon.HashAlgorithm
	// Optional hint of which signing key was used; will be included in bundle
	PublicKeyHint []byte
}

func SignerKeypair(opts *KeypairOptions) (*Keypair, error) {
	if opts.PublicKeyHint == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(opts.Signer.Public())
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)
		opts.PublicKeyHint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
	}

	return &Keypair{options: opts}, nil
}

func (k Keypair) Sign(content Content) (*protobundle.Bundle, error) {
	var hashFunc crypto.Hash

	switch k.options.HashAlgorithm {
	case protocommon.HashAlgorithm_SHA2_256:
		hashFunc = crypto.Hash(crypto.SHA256)
	case protocommon.HashAlgorithm_SHA2_384:
		hashFunc = crypto.Hash(crypto.SHA384)
	case protocommon.HashAlgorithm_SHA2_512:
		hashFunc = crypto.Hash(crypto.SHA512)
	default:
		return nil, errors.New("Unsupported hash algorithm")
	}

	hasher := hashFunc.New()
	hasher.Write(content.Prepare())
	digest := hasher.Sum(nil)

	signature, err := k.options.Signer.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return nil, err
	}

	bundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: string(k.options.PublicKeyHint),
				},
			},
		},
	}

	content.Bundle(bundle, k.options.HashAlgorithm, digest, signature)

	return bundle, nil
}
