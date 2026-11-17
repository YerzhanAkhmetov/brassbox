package crypto

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastKDF — лёгкие параметры, чтобы тесты шли быстро (логика та же).
var fastKDF = KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

func TestSealOpen(t *testing.T) {
	key, other := NewKey(), NewKey()
	plain, aad := []byte("секрет"), []byte("item:1/field:2")

	blob, err := Seal(key, plain, aad)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(blob, plain), "открытый текст в шифротексте")

	flip := func(i int) []byte {
		b := bytes.Clone(blob)
		b[i] ^= 1
		return b
	}

	cases := []struct {
		Name    string
		Key     []byte
		Blob    []byte
		AAD     []byte
		WantErr error // nil = должно открыться
	}{
		// ---- успех ----
		{Name: "тот же ключ и AAD", Key: key, Blob: blob, AAD: aad},
		// ---- не тот ключ / AAD ----
		{Name: "чужой ключ", Key: other, Blob: blob, AAD: aad, WantErr: ErrOpen},
		{Name: "другой AAD", Key: key, Blob: blob, AAD: []byte("item:1/field:3"), WantErr: ErrOpen},
		{Name: "без AAD", Key: key, Blob: blob, AAD: nil, WantErr: ErrOpen},
		// ---- подмена байта ----
		{Name: "байт в nonce", Key: key, Blob: flip(0), AAD: aad, WantErr: ErrOpen},
		{Name: "байт в шифротексте", Key: key, Blob: flip(13), AAD: aad, WantErr: ErrOpen},
		{Name: "байт в теге", Key: key, Blob: flip(len(blob) - 1), AAD: aad, WantErr: ErrOpen},
		// ---- кривые данные ----
		{Name: "пусто", Key: key, Blob: nil, AAD: aad, WantErr: ErrOpen},
		{Name: "короче nonce+тег", Key: key, Blob: blob[:27], AAD: aad, WantErr: ErrOpen},
		{Name: "обрезан хвост", Key: key, Blob: blob[:len(blob)-1], AAD: aad, WantErr: ErrOpen},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := Open(tc.Key, tc.Blob, tc.AAD)
			if tc.WantErr != nil {
				require.ErrorIs(t, err, tc.WantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, plain, got)
		})
	}
}

func TestSealNonceUnique(t *testing.T) {
	key := NewKey()
	a, err := Seal(key, []byte("x"), nil)
	require.NoError(t, err)
	b, err := Seal(key, []byte("x"), nil)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "одинаковый текст должен давать разный шифротекст (случайный nonce)")
}

func TestBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		_, err := Seal(make([]byte, n), []byte("x"), nil)
		assert.Error(t, err, "Seal, длина %d", n)
		_, err = Open(make([]byte, n), make([]byte, 64), nil)
		assert.Error(t, err, "Open, длина %d", n)
		_, err = SubKey(make([]byte, n), "x")
		assert.Error(t, err, "SubKey, длина %d", n)
	}
}

func TestNewKeyRandom(t *testing.T) {
	a, b := NewKey(), NewKey()
	assert.Len(t, a, KeySize)
	assert.Len(t, NewSalt(), SaltSize)
	assert.NotEqual(t, a, b)
}

func TestWipe(t *testing.T) {
	k := NewKey()
	Wipe(k)
	assert.Equal(t, make([]byte, KeySize), k)
}

func TestFingerprint(t *testing.T) {
	key := NewKey()
	fp := Fingerprint(key)
	assert.Regexp(t, regexp.MustCompile(`^[0-9A-F]{4}(-[0-9A-F]{4}){3}$`), fp)
	assert.Equal(t, fp, Fingerprint(bytes.Clone(key)), "один ключ — один отпечаток")
	assert.NotEqual(t, fp, Fingerprint(NewKey()))
}

func TestDeriveKey(t *testing.T) {
	salt := NewSalt()
	k1, err := DeriveKey("пароль-123", salt, fastKDF)
	require.NoError(t, err)
	require.Len(t, k1, KeySize)

	same, err := DeriveKey("пароль-123", bytes.Clone(salt), fastKDF)
	require.NoError(t, err)
	assert.Equal(t, k1, same, "тот же пароль и соль — тот же ключ")

	otherSalt, err := DeriveKey("пароль-123", NewSalt(), fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, k1, otherSalt, "другая соль — другой ключ")

	otherPass, err := DeriveKey("пароль-124", salt, fastKDF)
	require.NoError(t, err)
	assert.NotEqual(t, k1, otherPass, "другой пароль — другой ключ")

	otherParams, err := DeriveKey("пароль-123", salt, KDFParams{MemoryKiB: 64, Time: 2, Threads: 1})
	require.NoError(t, err)
	assert.NotEqual(t, k1, otherParams, "другие параметры — другой ключ")

	_, err = DeriveKey("x", salt[:8], fastKDF)
	assert.Error(t, err, "короткая соль")
}

func TestKDFValidate(t *testing.T) {
	cases := []struct {
		Name string
		P    KDFParams
		OK   bool
	}{
		// ---- норма ----
		{Name: "по умолчанию", P: DefaultKDF, OK: true},
		{Name: "лёгкие для тестов", P: fastKDF, OK: true},
		{Name: "максимум", P: KDFParams{MemoryKiB: maxMemoryKiB, Time: maxTime, Threads: maxThreads}, OK: true},
		// ---- вне границ (испорченный / подделанный файл) ----
		{Name: "ноль проходов", P: KDFParams{MemoryKiB: 64, Time: 0, Threads: 1}},
		{Name: "ноль потоков", P: KDFParams{MemoryKiB: 64, Time: 1, Threads: 0}},
		{Name: "память меньше 8 на поток", P: KDFParams{MemoryKiB: 31, Time: 1, Threads: 4}},
		{Name: "память больше 1 ГиБ", P: KDFParams{MemoryKiB: maxMemoryKiB + 1, Time: 1, Threads: 1}},
		{Name: "слишком много проходов", P: KDFParams{MemoryKiB: 64, Time: maxTime + 1, Threads: 1}},
		{Name: "слишком много потоков", P: KDFParams{MemoryKiB: 1024, Time: 1, Threads: maxThreads + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			err := tc.P.Validate()
			if tc.OK {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrKDFParams)
			_, err = DeriveKey("x", NewSalt(), tc.P)
			assert.ErrorIs(t, err, ErrKDFParams)
		})
	}
}

func TestSubKey(t *testing.T) {
	dek := NewKey()
	secret, err := SubKey(dek, "brassbox/secret/v1")
	require.NoError(t, err)
	require.Len(t, secret, KeySize)
	assert.NotEqual(t, dek, secret, "подключ не равен основному")

	again, err := SubKey(dek, "brassbox/secret/v1")
	require.NoError(t, err)
	assert.Equal(t, secret, again, "детерминирован")

	other, err := SubKey(dek, "brassbox/check/v1")
	require.NoError(t, err)
	assert.NotEqual(t, secret, other, "другая цель — другой ключ")
}
