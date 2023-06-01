package root

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSigstoreTrustedRoot(t *testing.T) {
	trustedrootJSON, err := os.ReadFile("../../examples/trusted-root-public-good.json")
	assert.Nil(t, err)

	trustedRoot, err := NewTrustedRootFromJSON(trustedrootJSON)
	assert.Nil(t, err)
	assert.NotNil(t, trustedRoot)
}
