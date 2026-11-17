// Package crypto — шифрование Brassbox: AES-256-GCM, Argon2id, HKDF.
// Библиотека чистых функций без состояния и зависимостей, поэтому без фасада и подпакета service.
//
// Формат шифротекста Seal: nonce 12 байт | шифротекст | тег 16 байт.
// AAD (дополнительные данные) не шифруются, но проверяются: шифротекст нельзя
// подменить или переставить в другое место (например, поменять замки местами).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// KeySize — длина ключа AES-256 (байт).
const KeySize = 32

// SaltSize — длина соли для Argon2id (байт).
const SaltSize = 16

// ErrOpen — тег GCM не сошёлся: не тот ключ, не те AAD или данные испорчены.
var ErrOpen = errors.New("crypto: key does not match or data is damaged")

// NewKey — случайный ключ 32 байта из crypto/rand.
func NewKey() []byte {
	return Random(KeySize)
}

// NewSalt — случайная соль 16 байт.
func NewSalt() []byte {
	return Random(SaltSize)
}

// Random — n случайных байт из crypto/rand.
func Random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read не возвращает ошибку (Go 1.24+)
	return b
}

// Seal шифрует plain ключом key; nonce случайный.
func Seal(key, plain, aad []byte) ([]byte, error) {
	g, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := Random(g.NonceSize())
	return g.Seal(nonce, nonce, plain, aad), nil
}

// Open расшифровывает результат Seal. ErrOpen — если ключ, AAD или данные не те.
func Open(key, blob, aad []byte) ([]byte, error) {
	g, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize()+g.Overhead() {
		return nil, ErrOpen
	}
	plain, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

// Wipe затирает байты в памяти (ключи, пароли) — насколько позволяет Go.
func Wipe(b []byte) {
	clear(b)
}

// Fingerprint — отпечаток ключа для людей: XXXX-XXXX-XXXX-XXXX.
// По нему сверяют ключ и копию; сам ключ из отпечатка не получить.
func Fingerprint(key []byte) string {
	h := sha256.Sum256(append([]byte("brassbox/fingerprint/v1:"), key...))
	s := strings.ToUpper(fmt.Sprintf("%x", h[:8]))
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key length %d, want %d", len(key), KeySize)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes: %w", err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm: %w", err)
	}
	return g, nil
}
