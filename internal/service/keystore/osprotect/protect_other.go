//go:build !darwin && !windows

// Package osprotect — привязка ключа к учётной записи ОС: Keychain (Mac), DPAPI (Windows).
package osprotect

import "errors"

var errUnsupported = errors.New("osprotect: this OS is not supported")

// Protector — на прочих ОС (Linux) защиты нет: решения, чем привязать ключ, пока нет.
type Protector struct{}

// New — заглушка, всегда ошибка.
func New(string) Protector { return Protector{} }

// Protect — не поддерживается.
func (Protector) Protect([]byte) ([]byte, error) { return nil, errUnsupported }

// Unprotect — не поддерживается.
func (Protector) Unprotect([]byte) ([]byte, error) { return nil, errUnsupported }
