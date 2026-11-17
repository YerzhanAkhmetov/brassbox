// Настоящий DPAPI: запускается только на Windows (keystore.test.exe).
package osprotect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"brassbox/internal/service/crypto"
)

func TestDPAPIRoundTrip(t *testing.T) {
	p := New("Brassbox-test")
	key := crypto.NewKey()

	blob, err := p.Protect(key)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), string(key))

	got, err := p.Unprotect(blob)
	require.NoError(t, err)
	assert.Equal(t, key, got)

	bad := append([]byte{}, blob...)
	bad[len(bad)/2] ^= 1
	_, err = p.Unprotect(bad)
	assert.Error(t, err, "испорченный blob")

	_, err = p.Unprotect([]byte("not dpapi"))
	assert.Error(t, err, "мусор")
}
