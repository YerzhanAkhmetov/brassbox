// Package model — формат файла .pvkey (JSON). []byte в JSON — base64.
package model

// PVKey — файл копии ключа.
type PVKey struct {
	Format      string `json:"format"`  // constant.PVKeyFormat
	Version     int    `json:"version"` // constant.PVKeyVersion
	Fingerprint string `json:"fingerprint"`

	// Без пароля — ключ как есть.
	Key []byte `json:"key,omitempty"`

	// С паролем — ключ под AES-GCM, ключ шифра — Argon2id(пароль).
	KDF    *KDF   `json:"kdf,omitempty"`
	Sealed []byte `json:"sealed,omitempty"`
}

// KDF — параметры Argon2id и соль.
type KDF struct {
	Alg       string `json:"alg"` // constant.PVKeyAlg
	MemoryKiB uint32 `json:"m"`
	Time      uint32 `json:"t"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
}
