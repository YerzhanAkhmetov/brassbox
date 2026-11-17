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

// texts — текст для пользователя по коду. Коротко, без технических деталей.
var texts = map[Err]string{
	Internal:       "Что-то пошло не так. Подробности — в журнале.",
	InvalidRequest: "Неверные данные.",
	ObjectNotFound: "Не найдено.",
	NotImplemented: "Пока не сделано.",
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
