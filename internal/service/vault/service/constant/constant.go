// Package constant — локальные константы vault.
package constant

// Автокопии: backups/<имя базы>/2026-11-17_21-05-33.pwv (своя папка у каждой базы).
const (
	BackupLayout = "2006-01-02_15-04-05"
	BackupDay    = "2006-01-02"
	BackupExt    = ".pwv"
	BackupTmp    = ".tmp-" // недописанная копия; при сбое удаляется
	DefaultKeep  = 3       // решение 2026-11-09: 0 / 1 / 3, по умолчанию 3
)

// BackupPattern — имя автокопии (только такие файлы удаляет ротация).
const BackupPattern = `^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(-\d+)?\.pwv$`

// SecretInfo — цель HKDF для ключа секретных полей (§23 «Схема шифрования»).
const SecretInfo = "brassbox/secret/v1"
