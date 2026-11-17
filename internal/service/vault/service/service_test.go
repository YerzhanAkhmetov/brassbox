package service

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
	headerService "brassbox/internal/service/header/service"
	headerConstant "brassbox/internal/service/header/service/constant"
	"brassbox/internal/service/vault"
	"brassbox/internal/storage"
)

var _ vault.Vault = (*Service)(nil)

var fastKDF = crypto.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const pass = "пароль-базы-1"

// clock — время, которое двигает тест.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	hdr     *headerService.Service
	clk     *clock
	dir     string // vaults/
	backups string // backups/
	master  []byte
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		hdr:     headerService.New(headerService.WithKDF(fastKDF)),
		clk:     &clock{t: time.Date(2026, 11, 17, 21, 5, 33, 0, time.Local)},
		dir:     filepath.Join(root, "vaults"),
		backups: filepath.Join(root, "backups"),
		master:  crypto.NewKey(),
	}
	require.NoError(t, os.MkdirAll(e.dir, 0o700))
	return e
}

func (e *env) svc(t *testing.T, list []storage.Migration, opts ...Option) *Service {
	t.Helper()
	all := append([]Option{WithMigrations(list), WithClock(e.clk.now)}, opts...)
	s, err := New(e.hdr, e.backups, all...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (e *env) path(name string) string { return filepath.Join(e.dir, name+".pwv") }

func (e *env) dek(t *testing.T, path string) []byte {
	t.Helper()
	dek, err := e.hdr.UnlockMaster(path, e.master)
	require.NoError(t, err)
	return dek
}

func (e *env) backupList(t *testing.T, vaultName string) []string {
	t.Helper()
	names, err := backups(filepath.Join(e.backups, vaultName))
	require.NoError(t, err)
	return names
}

func migrations(sqls ...string) []storage.Migration {
	list := make([]storage.Migration, len(sqls))
	for i, s := range sqls {
		list[i] = storage.Migration{Version: i + 1, Name: "m", SQL: s}
	}
	return list
}

var (
	m1 = migrations("CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")
	m2 = migrations(
		"CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
		"ALTER TABLE item ADD COLUMN fav INTEGER NOT NULL DEFAULT 0;",
	)
)

func version(t *testing.T, db *sql.DB) int {
	t.Helper()
	v, err := storage.Version(context.Background(), db)
	require.NoError(t, err)
	return v
}

func insert(t *testing.T, s *Service, name string) {
	t.Helper()
	db, err := s.DB()
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), "INSERT INTO item (name) VALUES (?)", name)
	require.NoError(t, err)
}

func count(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT count(*) FROM item").Scan(&n))
	return n
}

func TestOffsetMatchesHeader(t *testing.T) {
	assert.Equal(t, headerConstant.Size, storage.HeaderOffset, "сдвиг базы = размер заголовка")
}

func TestCreateOpenClose(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.svc(t, m1)
	path := e.path("vault")

	_, ok := s.Active()
	assert.False(t, ok)
	_, err := s.DB()
	require.ErrorIs(t, err, errs.VaultNotOpen)

	require.NoError(t, s.Create(ctx, path, e.master, pass))
	got, ok := s.Active()
	require.True(t, ok)
	assert.Equal(t, path, got)
	insert(t, s, "почта")

	key, err := s.SecretKey()
	require.NoError(t, err)
	assert.Len(t, key, crypto.KeySize)
	assert.NotEqual(t, e.dek(t, path), key, "ключ секретов ≠ DEK")

	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "второй Close — ничего")
	_, err = s.DB()
	require.ErrorIs(t, err, errs.VaultNotOpen)
	_, err = s.SecretKey()
	require.ErrorIs(t, err, errs.VaultNotOpen)
	require.ErrorIs(t, s.CopyTo(ctx, filepath.Join(e.dir, "c.pwv")), errs.VaultNotOpen)

	// ---- открыть снова: мастер-ключом и паролем ----
	require.NoError(t, s.Open(ctx, path, e.dek(t, path)))
	db, err := s.DB()
	require.NoError(t, err)
	assert.Equal(t, 1, count(t, db))
	require.NoError(t, s.Close())

	dek, err := e.hdr.UnlockPassword(path, pass)
	require.NoError(t, err)
	require.NoError(t, s.Open(ctx, path, dek))
	assert.Len(t, e.backupList(t, "vault"), 1, "при создании копии нет; первое открытие за день — одна копия, второе — без новой")
}

func TestCreateErrors(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.svc(t, m1)
	path := e.path("vault")
	require.NoError(t, s.Create(ctx, path, e.master, ""))
	require.NoError(t, s.Close())
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	require.ErrorIs(t, s.Create(ctx, path, e.master, ""), errs.VaultExists)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "существующий файл не тронут")

	// Миграция упала при создании — недописанный файл убран.
	bad := e.svc(t, migrations("CREATE TABLE x (; broken"))
	p2 := e.path("broken")
	require.Error(t, bad.Create(ctx, p2, e.master, ""))
	assert.NoFileExists(t, p2)
	_, ok := bad.Active()
	assert.False(t, ok)
}

func TestOpenWrongKey(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.svc(t, m1)
	a, b := e.path("a"), e.path("b")
	require.NoError(t, s.Create(ctx, b, e.master, ""))
	require.NoError(t, s.Create(ctx, a, e.master, ""))

	require.ErrorIs(t, s.Open(ctx, b, crypto.NewKey()), errs.KeyWrong)
	got, ok := s.Active()
	require.True(t, ok)
	assert.Equal(t, a, got, "неудача не закрыла открытую базу")

	require.ErrorIs(t, s.Open(ctx, e.path("none"), crypto.NewKey()), errs.ObjectNotFound)
}

func TestSwitchVaults(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.svc(t, m1)
	a, b := e.path("a"), e.path("b")
	require.NoError(t, s.Create(ctx, a, e.master, ""))
	dbA, err := s.DB()
	require.NoError(t, err)

	require.NoError(t, s.Create(ctx, b, e.master, ""))
	got, _ := s.Active()
	assert.Equal(t, b, got)
	assert.Error(t, dbA.PingContext(ctx), "прежняя база закрыта")

	require.NoError(t, s.Open(ctx, b, e.dek(t, b)), "повторное открытие той же — ничего")
	dbB, err := s.DB()
	require.NoError(t, err)
	assert.NoError(t, dbB.PingContext(ctx))
}

func TestMigrationBackup(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")

	s1 := e.svc(t, m1, WithKeep(0)) // ежедневные выключены — копия перед миграцией всё равно
	require.NoError(t, s1.Create(ctx, path, e.master, ""))
	insert(t, s1, "до миграции")
	require.NoError(t, s1.Close())

	s2 := e.svc(t, m2, WithKeep(0))
	require.NoError(t, s2.Open(ctx, path, e.dek(t, path)))
	db, err := s2.DB()
	require.NoError(t, err)
	assert.Equal(t, 2, version(t, db))
	require.NoError(t, s2.Close())

	list := e.backupList(t, "vault")
	require.Len(t, list, 1, "копия перед миграцией")
	assert.Equal(t, "2026-11-17_21-05-33.pwv", list[0])

	// Копия — полноценная база: заголовок, тот же ключ, схема до миграции.
	cp := filepath.Join(e.backups, "vault", list[0])
	dek := e.dek(t, cp)
	cdb, err := storage.Open(ctx, cp, dek)
	require.NoError(t, err)
	defer func() { _ = cdb.Close() }()
	assert.Equal(t, 1, version(t, cdb))
	assert.Equal(t, 1, count(t, cdb))
	raw, err := os.ReadFile(cp)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(raw, []byte("до миграции")), "копия зашифрована")
}

func TestFailedMigration(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")
	s1 := e.svc(t, m1)
	require.NoError(t, s1.Create(ctx, path, e.master, ""))
	insert(t, s1, "данные")
	require.NoError(t, s1.Close())

	bad := migrations(m1[0].SQL, "ALTER TABLE nope ADD COLUMN x INTEGER;")
	s2 := e.svc(t, bad)
	require.Error(t, s2.Open(ctx, path, e.dek(t, path)))
	_, ok := s2.Active()
	assert.False(t, ok, "не открыта")
	assert.Len(t, e.backupList(t, "vault"), 1, "копия перед миграцией осталась")

	require.NoError(t, s1.Open(ctx, path, e.dek(t, path)))
	db, err := s1.DB()
	require.NoError(t, err)
	assert.Equal(t, 1, version(t, db), "версия прежняя")
	assert.Equal(t, 1, count(t, db), "данные целы")
}

func TestVaultTooNew(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")
	s2 := e.svc(t, m2)
	require.NoError(t, s2.Create(ctx, path, e.master, ""))
	require.NoError(t, s2.Close())
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	old := e.svc(t, m1)
	require.ErrorIs(t, old.Open(ctx, path, e.dek(t, path)), errs.VaultTooNew)
	_, ok := old.Active()
	assert.False(t, ok)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "файл не тронут")
}

func TestDailyBackupsAndRotation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")
	s := e.svc(t, m1, WithKeep(3))
	require.NoError(t, s.Create(ctx, path, e.master, ""))
	require.NoError(t, s.Close())
	assert.Empty(t, e.backupList(t, "vault"), "пустая база при создании — без копии")

	reopen := func() {
		require.NoError(t, s.Open(ctx, path, e.dek(t, path)))
		require.NoError(t, s.Close())
	}

	// ---- один день — одна копия ----
	reopen()
	e.clk.add(time.Hour)
	reopen()
	assert.Len(t, e.backupList(t, "vault"), 1)

	// ---- чужие файлы в папке копий не трогаем ----
	dir := filepath.Join(e.backups, "vault")
	for _, name := range []string{"notes.txt", "2020-01-01_00-00-00.pwv.bak", "manual.pwv"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600))
	}

	// ---- 5 дней — остаются 3 новых ----
	for range 5 {
		e.clk.add(24 * time.Hour)
		reopen()
	}
	list := e.backupList(t, "vault")
	require.Len(t, list, 3)
	assert.Equal(t, []string{"2026-11-22_22-05-33.pwv", "2026-11-21_22-05-33.pwv", "2026-11-20_22-05-33.pwv"}, list)
	for _, name := range []string{"notes.txt", "2020-01-01_00-00-00.pwv.bak", "manual.pwv"} {
		assert.FileExists(t, filepath.Join(dir, name))
	}
	tmp, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	assert.Empty(t, tmp, "временных файлов нет")

	// ---- keep = 0: ежедневных нет, старые не удаляются ----
	off := e.svc(t, m1, WithKeep(0))
	e.clk.add(24 * time.Hour)
	require.NoError(t, off.Open(ctx, path, e.dek(t, path)))
	require.NoError(t, off.Close())
	assert.Len(t, e.backupList(t, "vault"), 3)
}

func TestBackupSameSecond(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")
	s := e.svc(t, m1)
	require.NoError(t, s.Create(ctx, path, e.master, ""))
	o := s.active
	dir := s.backupFolder(path)

	a, err := s.backup(ctx, o, dir)
	require.NoError(t, err)
	b, err := s.backup(ctx, o, dir)
	require.NoError(t, err)
	assert.Equal(t, "2026-11-17_21-05-33.pwv", filepath.Base(a))
	assert.Equal(t, "2026-11-17_21-05-33-2.pwv", filepath.Base(b), "не перезаписал, а взял -2")
}

func TestCopyTo(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")
	s := e.svc(t, m1)
	require.NoError(t, s.Create(ctx, path, e.master, pass))
	insert(t, s, "в копию")

	dst := filepath.Join(t.TempDir(), "флешка", "копия.pwv")
	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o700))
	require.NoError(t, s.CopyTo(ctx, dst))
	require.ErrorIs(t, s.CopyTo(ctx, dst), errs.VaultExists)

	// Копия открывается и паролем, и мастер-ключом — заголовок тот же.
	dek, err := e.hdr.UnlockPassword(dst, pass)
	require.NoError(t, err)
	cdb, err := storage.Open(ctx, dst, dek)
	require.NoError(t, err)
	defer func() { _ = cdb.Close() }()
	assert.Equal(t, 1, count(t, cdb))
	assert.Equal(t, e.dek(t, path), e.dek(t, dst))
}

func TestHeaderWriteWhileOpen(t *testing.T) {
	// ⚠️ из этапа 1: заголовок меняется своим os.File, пока база открыта SQLite (важно для Windows).
	ctx := context.Background()
	e := newEnv(t)
	path := e.path("vault")
	s := e.svc(t, m1)
	require.NoError(t, s.Create(ctx, path, e.master, ""))
	insert(t, s, "до")

	dek := e.dek(t, path)
	require.NoError(t, e.hdr.SetPassword(path, dek, pass))
	insert(t, s, "после")
	_, err := e.hdr.UnlockPassword(path, "неверный-пароль")
	require.ErrorIs(t, err, errs.PasswordWrong)
	require.NoError(t, e.hdr.RewrapMaster(path, dek, e.master))
	require.NoError(t, s.Close())

	got, err := e.hdr.UnlockPassword(path, pass)
	require.NoError(t, err)
	require.NoError(t, s.Open(ctx, path, got))
	db, err := s.DB()
	require.NoError(t, err)
	assert.Equal(t, 2, count(t, db), "база цела после правок заголовка")
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.svc(t, m1)
	a, b := e.path("a"), e.path("b")
	require.NoError(t, s.Create(ctx, a, e.master, ""))
	require.NoError(t, s.Create(ctx, b, e.master, ""))
	deks := map[string][]byte{a: e.dek(t, a), b: e.dek(t, b)}

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			p := a
			if i%2 == 0 {
				p = b
			}
			switch i % 4 {
			case 0, 1:
				assert.NoError(t, s.Open(ctx, p, deks[p]))
			case 2:
				_, _ = s.DB()
				_, _ = s.Active()
			case 3:
				assert.NoError(t, s.Close())
			}
		})
	}
	wg.Wait()
}
