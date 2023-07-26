package root

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
)

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

func TestTrustedMaterialCollection(t *testing.T) {
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
