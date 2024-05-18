package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetEphemeralKeyPair(t *testing.T) {

	ephemeralKeypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)
	assert.NotNil(t, ephemeralKeypair)
	assert.NotNil(t, ephemeralKeypair.options.Hint)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	assert.NotNil(t, key)
}

func TestGetEphemeralKeySHA2384(t *testing.T) {
	opts := EphemeralKeypairOptions{
		Hint:          nil,
		HashAlgorithm: protocommon.HashAlgorithm_SHA2_384,
	}

	ephemeralKeypair, err := NewEphemeralKeypair(&opts)
	assert.Nil(t, err)
	assert.NotNil(t, ephemeralKeypair)
	assert.NotNil(t, ephemeralKeypair.options.Hint)
}

func TestGetEphemeralKeySHA2512(t *testing.T) {
	opts := EphemeralKeypairOptions{
		Hint:          nil,
		HashAlgorithm: protocommon.HashAlgorithm_SHA2_512,
	}

	ephemeralKeypair, err := NewEphemeralKeypair(&opts)
	assert.Nil(t, err)
	assert.NotNil(t, ephemeralKeypair)
	assert.NotNil(t, ephemeralKeypair.options.Hint)
}

func TestGetEphemeralKeySHA3256(t *testing.T) {
	opts := EphemeralKeypairOptions{
		Hint:          nil,
		HashAlgorithm: protocommon.HashAlgorithm_SHA3_256,
	}

	ephemeralKeypair, err := NewEphemeralKeypair(&opts)
	assert.Nil(t, err)
	assert.NotNil(t, ephemeralKeypair)
	assert.NotNil(t, ephemeralKeypair.options.Hint)
}

func TestGetEphemeralKeySHA3384(t *testing.T) {
	opts := EphemeralKeypairOptions{
		Hint:          nil,
		HashAlgorithm: protocommon.HashAlgorithm_SHA3_384,
	}

	ephemeralKeypair, err := NewEphemeralKeypair(&opts)
	assert.Nil(t, err)
	assert.NotNil(t, ephemeralKeypair)
	assert.NotNil(t, ephemeralKeypair.options.Hint)
}

func TestGetAttributes(t *testing.T) {
	ephemeralKeypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)

	hashAlgorithm := ephemeralKeypair.GetHashAlgorithm()
	assert.NotNil(t, hashAlgorithm)

	keyAlgorithm := ephemeralKeypair.GetKeyAlgorithm()
	assert.Equal(t, "ECDSA", keyAlgorithm)

	hint := ephemeralKeypair.GetHint()
	assert.NotNil(t, hint)

	publicKeyPem, err := ephemeralKeypair.GetPublicKeyPem()
	assert.Nil(t, err)
	assert.NotNil(t, publicKeyPem)

	ephemeralKeypair.privateKey = &ecdsa.PrivateKey{}
	_, err = ephemeralKeypair.GetPublicKeyPem()
	assert.NotNil(t, err)
}

func TestHashFunc(t *testing.T) {
	hash, err := getHashFunc(protocommon.HashAlgorithm_SHA2_256)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	hash, err = getHashFunc(protocommon.HashAlgorithm_SHA2_384)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	hash, err = getHashFunc(protocommon.HashAlgorithm_SHA2_512)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	hash, err = getHashFunc(protocommon.HashAlgorithm_SHA3_384)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	hash, err = getHashFunc(protocommon.HashAlgorithm_SHA3_256)
	assert.Nil(t, err)
	assert.NotNil(t, hash)

	_, err = getHashFunc(protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	assert.NotNil(t, err)
}

func TestSignData(t *testing.T) {
	ephemeralKeypair, err := NewEphemeralKeypair(nil)
	assert.Nil(t, err)

	ephemeralKeypair.hashAlgorithm = protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	_, _, err = ephemeralKeypair.SignData([]byte("this is a test"))
	assert.NotNil(t, err)

	ephemeralKeypair.hashAlgorithm = protocommon.HashAlgorithm_SHA2_256
	signature, digest, err := ephemeralKeypair.SignData([]byte("this is a test"))
	assert.Nil(t, err)
	assert.NotNil(t, signature)
	assert.NotNil(t, digest)
}
