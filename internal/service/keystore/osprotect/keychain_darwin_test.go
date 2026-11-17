//go:build keychain

// Настоящий Keychain: запускать вручную на Mac —
//
//	go test -tags=keychain -count=1 ./internal/service/keystore/osprotect/
//
// Создаёт запись "Brassbox-test" и удаляет её в конце (настоящую "Brassbox" не трогает).
package osprotect

import (
	"testing"

	"github.com/keybase/go-keychain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"brassbox/internal/service/crypto"
)

const testService = "Brassbox-test"

func TestKeychainRoundTrip(t *testing.T) {
	_ = keychain.DeleteGenericPasswordItem(testService, kcAccount) // остаток прошлого прогона
	t.Cleanup(func() {
		_ = keychain.DeleteGenericPasswordItem(testService, kcAccount)
	})

	p := New(testService)
	key := crypto.NewKey()

	_, err := p.Unprotect([]byte("anything"))
	require.Error(t, err, "секрета ещё нет — Unprotect не должен его создавать")

	blob, err := p.Protect(key)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), string(key))

	got, err := p.Unprotect(blob)
	require.NoError(t, err)
	assert.Equal(t, key, got)

	blob2, err := p.Protect(key)
	require.NoError(t, err)
	got2, err := New(testService).Unprotect(blob2)
	require.NoError(t, err, "второй Protect берёт тот же секрет устройства")
	assert.Equal(t, key, got2)

	_, err = p.Unprotect(append([]byte{}, blob[:len(blob)-1]...))
	assert.Error(t, err, "испорченный blob")

	require.NoError(t, keychain.DeleteGenericPasswordItem(testService, kcAccount))
	_, err = p.Unprotect(blob)
	assert.Error(t, err, "секрет удалён (как после переустановки) — ключ не открывается")
}
