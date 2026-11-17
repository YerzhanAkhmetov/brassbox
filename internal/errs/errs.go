// Package errs — ошибки приложения: код (для логов и фронта) + русский текст (для экрана).
package errs

import "errors"

// Err — код ошибки (латиница, для логов и фронта).
type Err string

func (e Err) Error() string {
	return string(e)
}

// Общие ошибки. Новые — добавлять сюда и в texts.
const (
	Internal       = Err("internal")
	InvalidRequest = Err("invalid_request")
	ObjectNotFound = Err("object_not_found")
	NotImplemented = Err("not_implemented")
)

// Ключи и замки (этап 1).
const (
	KeyNotFound      = Err("key_not_found")
	KeyUnreadable    = Err("key_unreadable")
	KeyExists        = Err("key_exists")
	KeyWrong         = Err("key_wrong")
	PVKeyInvalid     = Err("pvkey_invalid")
	PasswordWrong    = Err("password_wrong")
	PasswordLocked   = Err("password_locked")
	PasswordNotSet   = Err("password_not_set")
	PasswordTooShort = Err("password_too_short")
	VaultInvalid     = Err("vault_invalid")
	VaultDamaged     = Err("vault_damaged")
	VaultExists      = Err("vault_exists")
)

// Хранилище (этап 2).
const (
	VaultCorrupt = Err("vault_corrupt")
	VaultTooNew  = Err("vault_too_new")
	VaultNotOpen = Err("vault_not_open")
)

// texts — текст для пользователя по коду. Коротко, без технических деталей.
var texts = map[Err]string{ //nolint:gosec // G101: user-facing texts, not credentials
	Internal:       "Что-то пошло не так. Подробности — в журнале.",
	InvalidRequest: "Неверные данные.",
	ObjectNotFound: "Не найдено.",
	NotImplemented: "Пока не сделано.",

	KeyNotFound:      "Мастер-ключ на этом компьютере не найден.",
	KeyUnreadable:    "Мастер-ключ на этом компьютере не открывается. Загрузите копию ключа (.pvkey).",
	KeyExists:        "Мастер-ключ уже есть — новый не создаём, чтобы не потерять доступ к данным.",
	KeyWrong:         "Ключ не подходит к этому хранилищу.",
	PVKeyInvalid:     "Это не копия ключа Brassbox, или файл повреждён.",
	PasswordWrong:    "Неверный пароль.",
	PasswordLocked:   "Пароль заблокирован после 5 неверных попыток. Откройте хранилище копией ключа (.pvkey) и задайте новый пароль.",
	PasswordNotSet:   "Пароль для этого хранилища не задан.",
	PasswordTooShort: "Пароль слишком короткий.",
	VaultInvalid:     "Это не хранилище Brassbox.",
	VaultDamaged:     "Заголовок хранилища повреждён. Восстановите хранилище из копии.",
	VaultExists:      "Такой файл уже есть — не перезаписываем.",

	VaultCorrupt: "Хранилище повреждено. Восстановите его из копии.",
	VaultTooNew:  "Хранилище создано более новой версией Brassbox. Обновите программу.",
	VaultNotOpen: "Хранилище не открыто.",
}

// ErrFull — ошибка с пояснением для журнала (Desc на экран не выводится).
type ErrFull struct {
	Err  Err
	Desc string
}

func (e ErrFull) Error() string {
	return e.Err.Error() + ", desc: " + e.Desc
}

func (e ErrFull) Unwrap() error {
	return e.Err
}

// Code — код ошибки из цепочки; незнакомая ошибка — Internal.
func Code(err error) Err {
	if e, ok := errors.AsType[Err](err); ok {
		return e
	}
	if e, ok := errors.AsType[ErrFull](err); ok {
		return e.Err
	}
	return Internal
}

// Text — русский текст для экрана; незнакомая ошибка — текст Internal.
func Text(err error) string {
	if t, ok := texts[Code(err)]; ok {
		return t
	}
	return texts[Internal]
}
