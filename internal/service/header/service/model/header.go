// Package model — JSON внутри копии заголовка. []byte в JSON — base64.
package model

// Header — одна копия заголовка.
type Header struct {
	Format  int    `json:"format"`   // constant.Format
	Seq     uint64 `json:"seq"`      // номер записи: живая копия — с большим
	VaultID []byte `json:"vault_id"` // 16 байт
	Fails   int    `json:"fails"`    // неверных паролей подряд
	Locked  bool   `json:"locked"`   // замок 1 стёрт после MaxFails
	// DEKCheck — первые 16 байт HKDF(DEK, "brassbox/dek-check/v1"): проверка, что DEK
	// верный, перед тем как закрыть им новый замок (иначе ошибка в коде = потерянная база).
	DEKCheck []byte        `json:"dek_check"`
	Password *PasswordLock `json:"password,omitempty"` // замок 1 (по желанию)
	Master   *MasterLock   `json:"master"`             // замок 2
}

// PasswordLock — DEK под ключом из пароля (Argon2id).
type PasswordLock struct {
	MemoryKiB uint32 `json:"m"`
	Time      uint32 `json:"t"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
	Sealed    []byte `json:"sealed"`
}

// MasterLock — DEK под мастер-ключом.
type MasterLock struct {
	Sealed []byte `json:"sealed"`
}
