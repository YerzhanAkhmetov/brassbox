package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFParams — параметры Argon2id. Хранятся рядом с солью (в заголовке, в .pvkey),
// поэтому их можно поднять позже, не ломая старые файлы.
type KDFParams struct {
	MemoryKiB uint32 // память, КиБ
	Time      uint32 // проходы
	Threads   uint8  // потоки
}

// DefaultKDF — решение §23: 64 МБ, 3 прохода, 4 потока.
var DefaultKDF = KDFParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 4}

// Границы параметров из файла: файл может быть испорчен или подделан —
// не даём ему съесть всю память или повесить программу.
const (
	maxMemoryKiB = 1024 * 1024 // 1 ГиБ
	maxTime      = 20
	maxThreads   = 16
)

// ErrKDFParams — параметры Argon2id вне допустимых границ.
var ErrKDFParams = errors.New("crypto: kdf params out of range")

// Validate проверяет границы параметров.
func (p KDFParams) Validate() error {
	if p.Time < 1 || p.Time > maxTime ||
		p.Threads < 1 || p.Threads > maxThreads ||
		p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxMemoryKiB {
		return fmt.Errorf("%w: memory=%d KiB, time=%d, threads=%d", ErrKDFParams, p.MemoryKiB, p.Time, p.Threads)
	}
	return nil
}

// DeriveKey — ключ 32 байта из пароля (Argon2id). Медленно нарочно: перебор паролей дорогой.
func DeriveKey(password string, salt []byte, p KDFParams) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) < SaltSize {
		return nil, fmt.Errorf("crypto: salt length %d, want >= %d", len(salt), SaltSize)
	}
	return argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, KeySize), nil
}

// SubKey — отдельный ключ из основного (HKDF-SHA256) для своей цели, info — имя цели.
// Например, ключ секретных полей = SubKey(DEK, "brassbox/secret/v1").
func SubKey(key []byte, info string) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key length %d, want %d", len(key), KeySize)
	}
	return hkdf.Key(sha256.New, key, nil, info, KeySize)
}
