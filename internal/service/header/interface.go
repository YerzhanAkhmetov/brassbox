// Package header — открытый заголовок файла хранилища (первые 4 КиБ vault.pwv).
//
// Внутри — ключ данных (DEK), закрытый двумя замками: замок 1 — паролем (по желанию),
// замок 2 — мастер-ключом; и счётчик неверных паролей (5 → замок 1 стирается).
// Сама база SQLite лежит после заголовка и шифруется DEK (этап 2).
package header

import headerModel "brassbox/internal/service/header/model"

// Header — что умеет модуль (витрина). Реализация — service.Service.
// Все методы работают с файлом path; база при этом может быть открыта
// (SQLite не трогает первые 4 КиБ).
type Header interface {
	// Create — новый файл с заголовком (errs.VaultExists, если файл есть).
	// password "" — без замка 1.
	Create(path string, dek, master []byte, password string) error
	// Read — что видно без ключа.
	Read(path string) (headerModel.Info, error)

	// UnlockPassword — DEK по паролю. Счётчик +1 записывается ДО проверки.
	// Ошибки: model.WrongPasswordError (errs.PasswordWrong), errs.PasswordLocked, errs.PasswordNotSet.
	UnlockPassword(path, password string) ([]byte, error)
	// UnlockMaster — DEK по мастер-ключу (errs.KeyWrong). Счётчик не трогает.
	UnlockMaster(path string, master []byte) ([]byte, error)

	// SetPassword — новый замок 1 (или замена), сбрасывает счётчик и блокировку.
	SetPassword(path string, dek []byte, password string) error
	// RemovePassword — убрать замок 1 (вход только по мастер-ключу).
	RemovePassword(path string, dek []byte) error
	// RewrapMaster — замок 2 под другой мастер-ключ (подключение чужой базы своим ключом).
	RewrapMaster(path string, dek, master []byte) error
}
