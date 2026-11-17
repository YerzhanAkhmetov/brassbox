// Package model — контрактные модели header.
package model

import (
	"fmt"

	"brassbox/internal/errs"
)

// Info — что видно в заголовке без ключа.
type Info struct {
	VaultID     []byte // 16 случайных байт, создаются один раз
	HasPassword bool   // замок 1 есть
	Locked      bool   // замок 1 стёрт после MaxFails неверных паролей
	Fails       int    // неверных паролей подряд
	Left        int    // осталось попыток до стирания замка 1
}

// WrongPasswordError — неверный пароль, осталось Left попыток. errors.Is(err, errs.PasswordWrong) == true.
type WrongPasswordError struct {
	Left int
}

func (e WrongPasswordError) Error() string {
	return fmt.Sprintf("%s, left: %d", errs.PasswordWrong, e.Left)
}

func (e WrongPasswordError) Unwrap() error {
	return errs.PasswordWrong
}
