package policy

import (
	"testing"

	"github.com/github/sigstore-verifier/pkg/testing/data"
	"github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
	bundle := data.SigstoreBundle(t)
	err := VerifyKeyless(bundle)
	assert.NoError(t, err)
}
