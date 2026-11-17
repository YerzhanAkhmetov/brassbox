// Package constant — локальные константы keystore.
package constant

// MasterMagic — начало файла master.key (дальше — ключ под защитой ОС).
const MasterMagic = "BRASSBOX-KEY/1\n"

// UnreadableSuffix — так переименовывается master.key, который не открылся, перед Store.
const UnreadableSuffix = ".unreadable"

// .pvkey
const (
	PVKeyFormat    = "brassbox-pvkey"
	PVKeyVersion   = 1
	PVKeyAlg       = "argon2id"
	PVKeyAADPrefix = "brassbox/pvkey/v1:" // + отпечаток ключа
	PVKeyMaxSize   = 64 << 10             // больше — точно не наш файл
	PVKeyMinPass   = 6                    // §18: минимум 6 символов, слабый не запрещаем
)
