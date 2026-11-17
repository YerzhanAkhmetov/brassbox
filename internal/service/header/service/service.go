// Package service — реализация header: замки, счётчик, чтение и запись копий заголовка.
package service

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"unicode/utf8"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
	headerModel "brassbox/internal/service/header/model"
	localConstant "brassbox/internal/service/header/service/constant"
	localModel "brassbox/internal/service/header/service/model"
)

// Service — операции с заголовком. Один на программу: mu не даёт двум операциям
// одновременно читать-менять-писать заголовок (счётчик попыток).
type Service struct {
	mu  sync.Mutex
	kdf crypto.KDFParams
}

// Option — необязательная настройка Service.
type Option func(*Service)

// WithKDF — параметры Argon2id для новых замков 1 (в тестах — лёгкие).
func WithKDF(p crypto.KDFParams) Option {
	return func(s *Service) { s.kdf = p }
}

// New — сервис заголовка.
func New(opts ...Option) *Service {
	s := &Service{kdf: crypto.DefaultKDF}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Create — новый файл: заголовок с замком 2 (и замком 1, если password не пустой).
func (s *Service) Create(path string, dek, master []byte, password string) error {
	if len(dek) != crypto.KeySize || len(master) != crypto.KeySize {
		return fmt.Errorf("%w: key length", errs.InvalidRequest)
	}
	if password != "" && utf8.RuneCountInString(password) < localConstant.MinPassword {
		return errs.PasswordTooShort
	}

	h := localModel.Header{
		Format:  localConstant.Format,
		Seq:     1,
		VaultID: crypto.Random(localConstant.VaultIDSize),
	}
	var err error
	if h.DEKCheck, err = dekCheck(dek); err != nil {
		return err
	}
	if h.Master, err = sealMaster(h.VaultID, dek, master); err != nil {
		return err
	}
	if password != "" {
		if h.Password, err = s.sealPassword(h.VaultID, dek, password); err != nil {
			return err
		}
	}
	slotA, err := encodeSlot(h, localConstant.SlotASize)
	if err != nil {
		return err
	}
	buf := make([]byte, localConstant.Size)
	copy(buf, localConstant.Magic)
	copy(buf[localConstant.SlotAOff:], slotA)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Путь даёт сама программа (папка данных / выбор пользователя в окне).
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path from app, not untrusted input
	if errors.Is(err, fs.ErrExist) {
		return errs.VaultExists
	}
	if err != nil {
		return fmt.Errorf("create vault file: %w", err)
	}
	_, err = f.WriteAt(buf, 0)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path) // свой недописанный файл
		return fmt.Errorf("write vault header: %w", err)
	}
	return nil
}

// Read — что видно без ключа.
func (s *Service) Read(path string) (headerModel.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := openFile(path, os.O_RDONLY)
	if err != nil {
		return headerModel.Info{}, err
	}
	defer func() { _ = f.Close() }()

	st, err := readState(f)
	if err != nil {
		return headerModel.Info{}, err
	}
	return headerModel.Info{
		VaultID:     st.h.VaultID,
		HasPassword: st.h.Password != nil,
		Locked:      st.h.Locked,
		Fails:       st.h.Fails,
		Left:        max(localConstant.MaxFails-st.h.Fails, 0),
	}, nil
}

// UnlockPassword — DEK по паролю. Счётчик +1 и запись — до проверки: прерванная
// на Argon2id программа всё равно потратила попытку.
func (s *Service) UnlockPassword(path, password string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := openFile(path, os.O_RDWR)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	st, err := readState(f)
	if err != nil {
		return nil, err
	}
	lock := st.h.Password
	if lock == nil {
		if st.h.Locked {
			return nil, errs.PasswordLocked
		}
		return nil, errs.PasswordNotSet
	}
	if password == "" { // пустой ввод — не попытка
		return nil, headerModel.WrongPasswordError{Left: max(localConstant.MaxFails-st.h.Fails, 0)}
	}

	st.h.Fails++
	if err := writeNext(f, &st); err != nil {
		return nil, err
	}

	p := crypto.KDFParams{MemoryKiB: lock.MemoryKiB, Time: lock.Time, Threads: lock.Threads}
	kek, err := crypto.DeriveKey(password, lock.Salt, p)
	if err != nil {
		return nil, fmt.Errorf("%w: password lock: %w", errs.VaultDamaged, err)
	}
	defer crypto.Wipe(kek)

	dek, err := crypto.Open(kek, lock.Sealed, aad(localConstant.AADPassword, st.h.VaultID))
	if err != nil {
		if st.h.Fails < localConstant.MaxFails {
			return nil, headerModel.WrongPasswordError{Left: localConstant.MaxFails - st.h.Fails}
		}
		st.h.Password, st.h.Locked = nil, true
		if err := writeNext(f, &st); err != nil {
			return nil, err
		}
		return nil, errs.PasswordLocked
	}
	if err := verifyDEK(st.h, dek); err != nil {
		crypto.Wipe(dek)
		return nil, fmt.Errorf("%w: password lock opens wrong key", errs.VaultDamaged)
	}

	st.h.Fails = 0
	if err := writeNext(f, &st); err != nil {
		crypto.Wipe(dek)
		return nil, err
	}
	return dek, nil
}

// UnlockMaster — DEK по мастер-ключу. Счётчик и блокировку пароля не меняет.
func (s *Service) UnlockMaster(path string, master []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := openFile(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	st, err := readState(f)
	if err != nil {
		return nil, err
	}
	if len(master) != crypto.KeySize {
		return nil, errs.KeyWrong
	}
	dek, err := crypto.Open(master, st.h.Master.Sealed, aad(localConstant.AADMaster, st.h.VaultID))
	if err != nil {
		return nil, errs.KeyWrong
	}
	if err := verifyDEK(st.h, dek); err != nil {
		crypto.Wipe(dek)
		return nil, fmt.Errorf("%w: master lock opens wrong key", errs.VaultDamaged)
	}
	return dek, nil
}

// SetPassword — новый замок 1; счётчик и блокировка сбрасываются.
func (s *Service) SetPassword(path string, dek []byte, password string) error {
	if utf8.RuneCountInString(password) < localConstant.MinPassword {
		return errs.PasswordTooShort
	}
	return s.update(path, dek, func(h *localModel.Header) error {
		lock, err := s.sealPassword(h.VaultID, dek, password)
		if err != nil {
			return err
		}
		h.Password, h.Locked, h.Fails = lock, false, 0
		return nil
	})
}

// RemovePassword — убрать замок 1.
func (s *Service) RemovePassword(path string, dek []byte) error {
	return s.update(path, dek, func(h *localModel.Header) error {
		h.Password, h.Locked, h.Fails = nil, false, 0
		return nil
	})
}

// RewrapMaster — замок 2 под другой мастер-ключ.
func (s *Service) RewrapMaster(path string, dek, master []byte) error {
	if len(master) != crypto.KeySize {
		return fmt.Errorf("%w: key length", errs.InvalidRequest)
	}
	return s.update(path, dek, func(h *localModel.Header) error {
		lock, err := sealMaster(h.VaultID, dek, master)
		if err != nil {
			return err
		}
		h.Master = lock
		return nil
	})
}

// Verify — DEK подходит к этому файлу.
func (s *Service) Verify(path string, dek []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := openFile(path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	st, err := readState(f)
	if err != nil {
		return err
	}
	return verifyDEK(st.h, dek)
}

// Clone — заголовок src (как есть, обе копии) в начало существующего dst.
func (s *Service) Clone(src, dst string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	in, err := openFile(src, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if _, err := readState(in); err != nil { // источник — целый заголовок Brassbox
		return err
	}
	buf := make([]byte, localConstant.Size)
	if _, err := in.ReadAt(buf, 0); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	out, err := openFile(dst, os.O_RDWR)
	if err != nil {
		return err
	}
	_, err = out.WriteAt(buf, 0)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write header copy: %w", err)
	}
	return nil
}

// update — прочитать, проверить DEK, изменить, записать в другую копию.
func (s *Service) update(path string, dek []byte, change func(*localModel.Header) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := openFile(path, os.O_RDWR)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	st, err := readState(f)
	if err != nil {
		return err
	}
	if err := verifyDEK(st.h, dek); err != nil {
		return err
	}
	if err := change(&st.h); err != nil {
		return err
	}
	return writeNext(f, &st)
}

func (s *Service) sealPassword(vaultID, dek []byte, password string) (*localModel.PasswordLock, error) {
	salt := crypto.NewSalt()
	kek, err := crypto.DeriveKey(password, salt, s.kdf)
	if err != nil {
		return nil, fmt.Errorf("derive password key: %w", err)
	}
	defer crypto.Wipe(kek)
	sealed, err := crypto.Seal(kek, dek, aad(localConstant.AADPassword, vaultID))
	if err != nil {
		return nil, fmt.Errorf("seal password lock: %w", err)
	}
	return &localModel.PasswordLock{
		MemoryKiB: s.kdf.MemoryKiB,
		Time:      s.kdf.Time,
		Threads:   s.kdf.Threads,
		Salt:      salt,
		Sealed:    sealed,
	}, nil
}

func sealMaster(vaultID, dek, master []byte) (*localModel.MasterLock, error) {
	sealed, err := crypto.Seal(master, dek, aad(localConstant.AADMaster, vaultID))
	if err != nil {
		return nil, fmt.Errorf("seal master lock: %w", err)
	}
	return &localModel.MasterLock{Sealed: sealed}, nil
}

func dekCheck(dek []byte) ([]byte, error) {
	k, err := crypto.SubKey(dek, localConstant.CheckInfo)
	if err != nil {
		return nil, fmt.Errorf("dek check: %w", err)
	}
	return k[:localConstant.CheckSize], nil
}

// verifyDEK — DEK тот, что в этом заголовке (errs.KeyWrong).
func verifyDEK(h localModel.Header, dek []byte) error {
	c, err := dekCheck(dek)
	if err != nil {
		return fmt.Errorf("%w: %w", errs.KeyWrong, err)
	}
	if subtle.ConstantTimeCompare(c, h.DEKCheck) != 1 {
		return errs.KeyWrong
	}
	return nil
}

func aad(prefix string, vaultID []byte) []byte {
	return append([]byte(prefix), vaultID...)
}

func openFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag, 0) //nolint:gosec // G304: path from app, not untrusted input
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: vault file", errs.ObjectNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("open vault file: %w", err)
	}
	return f, nil
}
