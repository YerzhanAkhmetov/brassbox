// Package service — реализация vault.
package service

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
	localConstant "brassbox/internal/service/vault/service/constant"
	"brassbox/internal/storage"
)

// Service — одна активная база. mu защищает active (вызовы с фронта идут параллельно).
type Service struct {
	mu     sync.Mutex
	header headerI

	backupDir  string
	keep       int
	migrations []storage.Migration
	now        func() time.Time
	log        *slog.Logger

	active *opened
}

// opened — открытая база.
type opened struct {
	path string
	db   *sql.DB
	dek  []byte
}

// Option — необязательная настройка Service.
type Option func(*Service)

// WithKeep — сколько автокопий хранить на базу (0 — не делать ежедневные).
func WithKeep(n int) Option {
	return func(s *Service) { s.keep = max(n, 0) }
}

// WithMigrations — свой список миграций (в тестах).
func WithMigrations(list []storage.Migration) Option {
	return func(s *Service) { s.migrations = list }
}

// WithClock — своё время (в тестах).
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// WithLogger — журнал (ошибки автокопий не мешают открыть базу, но пишутся сюда).
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.log = l }
}

// New — vault. backupDir — папка автокопий (обычно <данные>/backups).
// Миграции по умолчанию — storage.Migrations().
func New(header headerI, backupDir string, opts ...Option) (*Service, error) {
	s := &Service{
		header:    header,
		backupDir: backupDir,
		keep:      localConstant.DefaultKeep,
		now:       time.Now,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	list, err := storage.Migrations()
	if err != nil {
		return nil, err
	}
	s.migrations = list
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Create — новый файл с новым DEK и сразу открыть его.
func (s *Service) Create(ctx context.Context, path string, master []byte, password string) error {
	dek := crypto.NewKey()
	defer crypto.Wipe(dek)

	if err := s.header.Create(path, dek, master, password); err != nil {
		return err
	}
	if err := s.Open(ctx, path, dek); err != nil {
		_ = os.Remove(path) // свой только что созданный файл без данных
		return err
	}
	return nil
}

// Open — открыть базу; прежняя закрывается только после успеха.
func (s *Service) Open(ctx context.Context, path string, dek []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active != nil && s.active.path == path {
		return nil // уже открыта
	}
	if err := s.header.Verify(path, dek); err != nil {
		return err
	}
	db, err := storage.Open(ctx, path, dek)
	if err != nil {
		return err
	}
	o := &opened{path: path, db: db, dek: bytes.Clone(dek)}

	if err := s.prepare(ctx, o); err != nil {
		_ = closeOpened(ctx, o, false) // не открыли — ничего в файл не пишем
		return err
	}

	if s.active != nil {
		if err := closeOpened(ctx, s.active, true); err != nil {
			s.log.Warn("close previous vault", "err", err)
		}
	}
	s.active = o
	return nil
}

// prepare — автокопии и миграции.
// Копия перед миграцией обязательна (нет копии — не мигрируем); ежедневная — по возможности.
func (s *Service) prepare(ctx context.Context, o *opened) error {
	version, err := storage.Version(ctx, o.db)
	if err != nil {
		return fmt.Errorf("%w: %w", errs.VaultCorrupt, err)
	}
	pending, err := storage.Pending(ctx, o.db, s.migrations)
	if err != nil {
		return err
	}

	dir := s.backupFolder(o.path)
	if version > 0 { // в пустой базе беречь нечего
		switch {
		case pending > 0:
			if _, err := s.backup(ctx, o, dir); err != nil {
				return fmt.Errorf("backup before migration: %w", err)
			}
		case s.keep > 0 && !s.backedUpToday(dir):
			if _, err := s.backup(ctx, o, dir); err != nil {
				s.log.Warn("daily backup failed", "err", err)
			}
		}
	}

	if pending > 0 {
		if err := storage.Migrate(ctx, o.db, s.migrations); err != nil {
			return err
		}
	}
	if s.keep > 0 {
		if err := s.rotate(dir); err != nil {
			s.log.Warn("backup rotation failed", "err", err)
		}
	}
	return nil
}

// Close — закрыть активную базу.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil
	}
	err := closeOpened(context.Background(), s.active, true)
	s.active = nil
	return err
}

// Active — путь открытой базы.
func (s *Service) Active() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return "", false
	}
	return s.active.path, true
}

// DB — открытая база.
func (s *Service) DB() (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, errs.VaultNotOpen
	}
	return s.active.db, nil
}

// SecretKey — ключ секретных полей (HKDF от DEK). Вызывающий затирает после использования.
func (s *Service) SecretKey() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, errs.VaultNotOpen
	}
	return crypto.SubKey(s.active.dek, localConstant.SecretInfo)
}

// CopyTo — копия открытой базы в новый файл dst.
func (s *Service) CopyTo(ctx context.Context, dst string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return errs.VaultNotOpen
	}
	if err := storage.VacuumInto(ctx, s.active.db, dst, s.active.dek); err != nil {
		return err
	}
	if err := s.header.Clone(s.active.path, dst); err != nil {
		_ = os.Remove(dst) // своя недописанная копия
		return err
	}
	return nil
}

// closeOpened — (оптимизация статистики), закрытие, затирание DEK.
// Сжатие не нужно: auto_vacuum = FULL освобождает место сразу (решение этапа 2).
// optimize = false — база не открылась (например, новее программы): в файл не пишем.
func closeOpened(ctx context.Context, o *opened, optimize bool) error {
	if optimize {
		_, _ = o.db.ExecContext(ctx, "PRAGMA optimize")
	}
	err := o.db.Close()
	crypto.Wipe(o.dek)
	if err != nil {
		return fmt.Errorf("close vault: %w", err)
	}
	return nil
}
