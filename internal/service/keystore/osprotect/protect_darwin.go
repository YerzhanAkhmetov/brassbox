// Package osprotect — привязка ключа к учётной записи ОС: Keychain (Mac), DPAPI (Windows).
package osprotect

import (
	"errors"
	"fmt"

	"github.com/keybase/go-keychain"

	"brassbox/internal/service/crypto"
)

// Mac: в Keychain лежит случайный «секрет устройства» (только этот Mac, без синхронизации
// iCloud, доступен, когда Mac разблокирован). master.key зашифрован этим секретом.
const kcAccount = "device-secret"

var kcAAD = []byte("brassbox/keystore/v1")

// Protector — защита ключа системой. service — имя записи в Keychain
// ("Brassbox"; в тестах — "Brassbox-test", чтобы не трогать настоящую).
type Protector struct {
	service string
}

// New — защита через Keychain.
func New(service string) Protector {
	return Protector{service: service}
}

// Protect шифрует данные секретом устройства (создаёт его при первом вызове).
func (p Protector) Protect(plain []byte) ([]byte, error) {
	secret, err := p.deviceSecret(true)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(secret)
	return crypto.Seal(secret, plain, kcAAD)
}

// Unprotect расшифровывает данные секретом устройства.
func (p Protector) Unprotect(blob []byte) ([]byte, error) {
	secret, err := p.deviceSecret(false)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(secret)
	return crypto.Open(secret, blob, kcAAD)
}

func (p Protector) deviceSecret(create bool) ([]byte, error) {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(p.service)
	q.SetAccount(kcAccount)
	q.SetMatchLimit(keychain.MatchLimitOne)
	q.SetReturnData(true)
	res, err := keychain.QueryItem(q)
	if err != nil {
		return nil, fmt.Errorf("keychain query: %w", err)
	}
	if len(res) == 1 && len(res[0].Data) == crypto.KeySize {
		return res[0].Data, nil
	}
	if !create {
		return nil, errors.New("keychain: device secret not found")
	}

	secret := crypto.NewKey()
	it := keychain.NewGenericPassword(p.service, kcAccount, "Brassbox — секрет устройства", secret, "")
	it.SetSynchronizable(keychain.SynchronizableNo)
	it.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
	if err := keychain.AddItem(it); err != nil {
		crypto.Wipe(secret)
		return nil, fmt.Errorf("keychain add: %w", err)
	}
	return secret, nil
}
