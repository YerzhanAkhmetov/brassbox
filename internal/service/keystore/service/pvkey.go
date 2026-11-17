package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
	localConstant "brassbox/internal/service/keystore/service/constant"
	localModel "brassbox/internal/service/keystore/service/model"
)

// ExportPVKey — содержимое файла .pvkey. password "" — копия без пароля.
func (s *Service) ExportPVKey(key []byte, password string) ([]byte, error) {
	if len(key) != crypto.KeySize {
		return nil, fmt.Errorf("%w: key length %d", errs.InvalidRequest, len(key))
	}
	f := localModel.PVKey{
		Format:      localConstant.PVKeyFormat,
		Version:     localConstant.PVKeyVersion,
		Fingerprint: crypto.Fingerprint(key),
	}
	if password == "" {
		f.Key = key
		return json.MarshalIndent(f, "", "  ")
	}
	if utf8.RuneCountInString(password) < localConstant.PVKeyMinPass {
		return nil, errs.PasswordTooShort
	}

	salt := crypto.NewSalt()
	kek, err := crypto.DeriveKey(password, salt, s.kdf)
	if err != nil {
		return nil, fmt.Errorf("derive pvkey key: %w", err)
	}
	defer crypto.Wipe(kek)

	sealed, err := crypto.Seal(kek, key, pvkeyAAD(f.Fingerprint))
	if err != nil {
		return nil, fmt.Errorf("seal pvkey: %w", err)
	}
	f.KDF = &localModel.KDF{
		Alg:       localConstant.PVKeyAlg,
		MemoryKiB: s.kdf.MemoryKiB,
		Time:      s.kdf.Time,
		Threads:   s.kdf.Threads,
		Salt:      salt,
	}
	f.Sealed = sealed
	return json.MarshalIndent(f, "", "  ")
}

// PVKeyNeedsPassword — нужен ли пароль для этого .pvkey.
func (s *Service) PVKeyNeedsPassword(data []byte) (bool, error) {
	f, err := parsePVKey(data)
	if err != nil {
		return false, err
	}
	return f.KDF != nil, nil
}

// ImportPVKey — ключ из .pvkey. Неверный пароль — errs.PasswordWrong (счётчика попыток нет:
// перебор сдерживает Argon2id, файл и так у того, кто его держит).
func (s *Service) ImportPVKey(data []byte, password string) ([]byte, error) {
	f, err := parsePVKey(data)
	if err != nil {
		return nil, err
	}

	var key []byte
	if f.KDF == nil {
		key = f.Key
	} else {
		if password == "" {
			return nil, errs.PasswordWrong
		}
		p := crypto.KDFParams{MemoryKiB: f.KDF.MemoryKiB, Time: f.KDF.Time, Threads: f.KDF.Threads}
		kek, err := crypto.DeriveKey(password, f.KDF.Salt, p)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errs.PVKeyInvalid, err)
		}
		defer crypto.Wipe(kek)
		key, err = crypto.Open(kek, f.Sealed, pvkeyAAD(f.Fingerprint))
		if errors.Is(err, crypto.ErrOpen) {
			return nil, errs.PasswordWrong
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errs.PVKeyInvalid, err)
		}
	}

	if len(key) != crypto.KeySize || crypto.Fingerprint(key) != f.Fingerprint {
		crypto.Wipe(key)
		return nil, fmt.Errorf("%w: key does not match fingerprint", errs.PVKeyInvalid)
	}
	return key, nil
}

// parsePVKey — разбор и проверка формы файла (без расшифровки).
func parsePVKey(data []byte) (localModel.PVKey, error) {
	var f localModel.PVKey
	if len(data) == 0 || len(data) > localConstant.PVKeyMaxSize {
		return f, fmt.Errorf("%w: size %d", errs.PVKeyInvalid, len(data))
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("%w: %w", errs.PVKeyInvalid, err)
	}
	if f.Format != localConstant.PVKeyFormat || f.Version != localConstant.PVKeyVersion {
		return f, fmt.Errorf("%w: format %q v%d", errs.PVKeyInvalid, f.Format, f.Version)
	}
	plain, sealed := f.Key != nil, f.KDF != nil || f.Sealed != nil
	if plain == sealed {
		return f, fmt.Errorf("%w: need exactly one of key / kdf+sealed", errs.PVKeyInvalid)
	}
	if sealed && (f.KDF == nil || f.Sealed == nil || f.KDF.Alg != localConstant.PVKeyAlg) {
		return f, fmt.Errorf("%w: bad kdf", errs.PVKeyInvalid)
	}
	return f, nil
}

func pvkeyAAD(fingerprint string) []byte {
	return []byte(localConstant.PVKeyAADPrefix + fingerprint)
}
