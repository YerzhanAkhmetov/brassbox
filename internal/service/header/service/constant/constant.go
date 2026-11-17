// Package constant — локальные константы header: раскладка первых 4 КиБ файла.
//
//	0    .. 15    магия "BRASSBOX\x00v1" (+ нули)
//	16   .. 2047  копия A
//	2048 .. 4095  копия B
//
// Копия: длина JSON (4 байта, big-endian) | JSON | SHA-256(длина|JSON) | нули.
// Пишется всегда более старая (или испорченная) копия → обрыв записи не трогает живую.
package constant

// Size — размер заголовка; база SQLite начинается после него (VFS-сдвиг, этап 2).
const Size = 4096

// Magic — первые байты файла (как в прототипе).
const Magic = "BRASSBOX\x00v1"

// Копии заголовка.
const (
	MagicArea = 16
	SlotAOff  = MagicArea
	SlotBOff  = 2048
	SlotASize = SlotBOff - SlotAOff
	SlotBSize = Size - SlotBOff
	LenSize   = 4
	HashSize  = 32
)

// Format — версия JSON внутри копии.
const Format = 1

// MaxFails — неверных паролей подряд до стирания замка 1 (§23).
const MaxFails = 5

// MinPassword — минимум символов пароля базы (§23).
const MinPassword = 8

// VaultIDSize — длина id хранилища.
const VaultIDSize = 16

// AAD замков и проверки DEK: + id хранилища → замки нельзя поменять местами
// или перенести из другого файла.
const (
	AADPassword = "brassbox/lock/password/v1:" //nolint:gosec // G101: AAD label, not a credential
	AADMaster   = "brassbox/lock/master/v1:"
	CheckInfo   = "brassbox/dek-check/v1"
	CheckSize   = 16
)
