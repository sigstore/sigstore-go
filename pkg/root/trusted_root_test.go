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

package root

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"testing"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

const pkixRsa = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3wqI/TysUiKTgY1bz+wd
JfEOil4MEsRASKGzJddZ6x9hb+rn2UVoJmuxN62XI0TMoMn4mukgfCgY6jgTB58V
+/LaeSA8Wz1p4gOxhk1mcgbF4HyxR+xlRgYfH4iSbXy+Ez/8ZjM2OO68fKr4JZEA
5LXZkhJr32JqH+UiFw/wgSPWA8aV0AfRAXHdekJ48B1ChxJTrOJWSPTnj/E0lfLV
srJKtXDuC8T0vFmVU726tI6fODsEE6VrSahvw1ENUHzI34sbfrmrggwPO4iMAQvq
wu2gn2lx6ajWsh806FItiXN+DuizMnx4KMBI0IJynoQpWOFbstGiV0LygZkQ6soz
vwIDAQAB
-----END PUBLIC KEY-----`

const pkixEd25519 = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9wy4umF4RHQ8UQXo8fzEQNBWE4GsBMkCzQPAfHvkf/s=
-----END PUBLIC KEY-----`

func TestGetSigstoreTrustedRoot(t *testing.T) {
	trustedrootJSON, err := os.ReadFile("../../examples/trusted-root-public-good.json")
	assert.Nil(t, err)

	trustedRoot, err := NewTrustedRootFromJSON(trustedrootJSON)
	assert.Nil(t, err)
	assert.NotNil(t, trustedRoot)
}

type singleKeyVerifier struct {
	BaseTrustedMaterial
	verifier TimeConstrainedVerifier
}

func (f *singleKeyVerifier) PublicKeyVerifier(_ string) (TimeConstrainedVerifier, error) {
	return f.verifier, nil
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func TestTrustedMaterialCollectionECDSA(t *testing.T) {
	trustedrootJSON, err := os.ReadFile("../../examples/trusted-root-public-good.json")
	assert.NoError(t, err)

	trustedRoot, err := NewTrustedRootFromJSON(trustedrootJSON)
	assert.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	ecVerifier, err := signature.LoadECDSAVerifier(key.Public().(*ecdsa.PublicKey), crypto.SHA256)
	assert.NoError(t, err)

	verifier := &nonExpiringVerifier{ecVerifier}
	trustedMaterialCollection := TrustedMaterialCollection{trustedRoot, &singleKeyVerifier{verifier: verifier}}

	verifier2, err := trustedMaterialCollection.PublicKeyVerifier("foo")
	assert.NoError(t, err)
	assert.Equal(t, verifier, verifier2)
}

func TestTrustedMaterialCollectionED25519(t *testing.T) {
	trustedrootJSON, err := os.ReadFile("../../examples/trusted-root-public-good.json")
	assert.NoError(t, err)

	trustedRootProto, err := NewTrustedRootProtobuf(trustedrootJSON)
	assert.NoError(t, err)
	for _, ctlog := range trustedRootProto.Ctlogs {
		ctlog.PublicKey.KeyDetails = protocommon.PublicKeyDetails_PKIX_ED25519
		derBytes, _ := pem.Decode([]byte(pkixEd25519))
		ctlog.PublicKey.RawBytes = derBytes.Bytes
	}

	for _, tlog := range trustedRootProto.Tlogs {
		tlog.PublicKey.KeyDetails = protocommon.PublicKeyDetails_PKIX_ED25519
		derBytes, _ := pem.Decode([]byte(pkixEd25519))
		tlog.PublicKey.RawBytes = derBytes.Bytes
	}

	trustedRoot, err := NewTrustedRootFromProtobuf(trustedRootProto)
	assert.NoError(t, err)

	for _, tlog := range trustedRoot.rekorLogs {
		assert.Equal(t, tlog.SignatureHashFunc, crypto.SHA512)
	}

	key, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	ecVerifier, err := signature.LoadED25519Verifier(key)
	assert.NoError(t, err)

	verifier := &nonExpiringVerifier{ecVerifier}
	trustedMaterialCollection := TrustedMaterialCollection{trustedRoot, &singleKeyVerifier{verifier: verifier}}

	verifier2, err := trustedMaterialCollection.PublicKeyVerifier("foo")
	assert.NoError(t, err)
	assert.Equal(t, verifier, verifier2)
}

func TestTrustedMaterialCollectionRSA(t *testing.T) {
	trustedrootJSON, err := os.ReadFile("../../examples/trusted-root-public-good.json")
	assert.NoError(t, err)

	trustedRootProto, err := NewTrustedRootProtobuf(trustedrootJSON)
	assert.NoError(t, err)
	for _, ctlog := range trustedRootProto.Ctlogs {
		ctlog.PublicKey.KeyDetails = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
		derBytes, _ := pem.Decode([]byte(pkixRsa))
		ctlog.PublicKey.RawBytes = derBytes.Bytes
	}

	for _, tlog := range trustedRootProto.Tlogs {
		tlog.PublicKey.KeyDetails = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
		derBytes, _ := pem.Decode([]byte(pkixRsa))
		tlog.PublicKey.RawBytes = derBytes.Bytes
	}

	trustedRoot, err := NewTrustedRootFromProtobuf(trustedRootProto)
	assert.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	ecVerifier, err := signature.LoadRSAPKCS1v15Verifier(key.Public().(*rsa.PublicKey), crypto.SHA256)
	assert.NoError(t, err)

	verifier := &nonExpiringVerifier{ecVerifier}
	trustedMaterialCollection := TrustedMaterialCollection{trustedRoot, &singleKeyVerifier{verifier: verifier}}

	verifier2, err := trustedMaterialCollection.PublicKeyVerifier("foo")
	assert.NoError(t, err)
	assert.Equal(t, verifier, verifier2)
}
