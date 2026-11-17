// Package keystore — мастер-ключ на этом компьютере (keys/master.key) и его копия .pvkey.
//
// Ключ (32 случайных байта) лежит в файле зашифрованным защитой ОС: на Mac — секретом
// устройства из Keychain, на Windows — DPAPI (см. osprotect). Скопированный на другой
// компьютер master.key не откроется — переносится только .pvkey.
package keystore

// Keystore — что умеет модуль (витрина). Реализация — service.Service.
type Keystore interface {
	// Exists — есть ли файл ключа на компьютере.
	Exists() bool
	// Create — новый случайный ключ; существующий файл не трогает (errs.KeyExists).
	Create() ([]byte, error)
	// Load — ключ с компьютера (errs.KeyNotFound / errs.KeyUnreadable).
	Load() ([]byte, error)
	// Store — сохранить ключ из .pvkey: только если своего нет или он не открывается
	// (нечитаемый файл не удаляется, а переименовывается в master.key.unreadable).
	Store(key []byte) error

	// ExportPVKey — содержимое .pvkey: password "" — без пароля, иначе Argon2id + AES-GCM.
	ExportPVKey(key []byte, password string) ([]byte, error)
	// PVKeyNeedsPassword — нужен ли пароль, чтобы открыть этот .pvkey.
	PVKeyNeedsPassword(data []byte) (bool, error)
	// ImportPVKey — ключ из .pvkey (errs.PVKeyInvalid / errs.PasswordWrong).
	ImportPVKey(data []byte, password string) ([]byte, error)
}
