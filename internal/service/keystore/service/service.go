// Package service — реализация keystore: master.key на компьютере.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
	localConstant "brassbox/internal/service/keystore/service/constant"
)

// Service — мастер-ключ в файле path под защитой ОС.
type Service struct {
	path string
	prot Protector
	kdf  crypto.KDFParams
}

// Option — необязательная настройка Service.
type Option func(*Service)

// WithKDF — параметры Argon2id для новых .pvkey (в тестах — лёгкие).
func WithKDF(p crypto.KDFParams) Option {
	return func(s *Service) { s.kdf = p }
}

// New — keystore для файла path (обычно <данные>/keys/master.key).
func New(path string, prot Protector, opts ...Option) *Service {
	s := &Service{path: path, prot: prot, kdf: crypto.DefaultKDF}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Exists — есть ли файл ключа.
func (s *Service) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Create — новый ключ. Существующий файл не трогает (errs.KeyExists).
func (s *Service) Create() ([]byte, error) {
	key := crypto.NewKey()
	if err := s.write(key); err != nil {
		crypto.Wipe(key)
		return nil, err
	}
	return key, nil
}

// Load — ключ с компьютера.
func (s *Service) Load() ([]byte, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errs.KeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	if !bytes.HasPrefix(b, []byte(localConstant.MasterMagic)) {
		return nil, fmt.Errorf("%w: no magic", errs.KeyUnreadable)
	}
	key, err := s.prot.Unprotect(b[len(localConstant.MasterMagic):])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errs.KeyUnreadable, err)
	}
	if len(key) != crypto.KeySize {
		crypto.Wipe(key)
		return nil, fmt.Errorf("%w: key length %d", errs.KeyUnreadable, len(key))
	}
	return key, nil
}

// Store — сохранить ключ (из .pvkey). Рабочий ключ не заменяет (errs.KeyExists);
// нечитаемый файл переименовывает в master.key.unreadable (не удаляет).
func (s *Service) Store(key []byte) error {
	if len(key) != crypto.KeySize {
		return fmt.Errorf("%w: key length %d", errs.InvalidRequest, len(key))
	}
	if s.Exists() {
		old, err := s.Load()
		if err == nil {
			crypto.Wipe(old)
			return errs.KeyExists
		}
		if !errors.Is(err, errs.KeyUnreadable) {
			return err
		}
		if err := os.Rename(s.path, s.path+localConstant.UnreadableSuffix); err != nil {
			return fmt.Errorf("move unreadable master key: %w", err)
		}
	}
	return s.write(key)
}

// write — защитить ключ системой и записать новый файл (не перезаписывая существующий).
func (s *Service) write(key []byte) error {
	blob, err := s.prot.Protect(key)
	if err != nil {
		return fmt.Errorf("protect master key: %w", err)
	}
	return writeNew(s.path, append([]byte(localConstant.MasterMagic), blob...))
}

// writeNew пишет файл целиком или никак: временный файл → fsync → жёсткая ссылка на итоговое имя
// (ссылка, в отличие от rename, не перезаписывает существующий файл). Права — только владелец.
func writeNew(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir keys: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".key-*")
	if err != nil {
		return fmt.Errorf("write master key: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	if err != nil {
		return fmt.Errorf("write master key: %w", err)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return errs.KeyExists
		}
		return fmt.Errorf("write master key: %w", err)
	}
	return nil
}
