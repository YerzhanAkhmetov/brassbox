package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
)

// fakeHeader — первые 4 КиБ файла: вместо заголовка Brassbox метка, которую база не должна тронуть.
var fakeHeader = bytes.Repeat([]byte("HDR!"), HeaderOffset/4)

const secret = "секретная-строка-ABC-123"

func newFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "vault.pwv")
	require.NoError(t, os.WriteFile(p, fakeHeader, 0o600))
	return p
}

func openT(t *testing.T, path string, dek []byte) *sql.DB {
	t.Helper()
	db, err := Open(context.Background(), path, dek)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func fill(t *testing.T, db *sql.DB, rows int) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, s TEXT NOT NULL)")
	require.NoError(t, err)
	for range rows {
		_, err = db.ExecContext(ctx, "INSERT INTO t (s) VALUES (?)", secret+strings.Repeat("x", 500))
		require.NoError(t, err)
	}
}

func pragma(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var v string
	require.NoError(t, db.QueryRowContext(context.Background(), "PRAGMA "+name).Scan(&v))
	return v
}

func TestOpenNewAndReopen(t *testing.T) {
	ctx := context.Background()
	path := newFile(t, t.TempDir())
	dek := crypto.NewKey()

	db, err := Open(ctx, path, dek)
	require.NoError(t, err)
	assert.Equal(t, "4096", pragma(t, db, "page_size"))
	assert.Equal(t, "1", pragma(t, db, "auto_vacuum"), "FULL")
	assert.Equal(t, "delete", pragma(t, db, "journal_mode"))
	assert.Equal(t, "2", pragma(t, db, "synchronous"), "FULL")
	assert.Equal(t, "1", pragma(t, db, "foreign_keys"))
	fill(t, db, 20)
	require.NoError(t, db.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, fakeHeader, raw[:HeaderOffset], "первые 4 КиБ не тронуты")
	assert.Zero(t, (len(raw)-HeaderOffset)%PageSize, "после заголовка — целые страницы")
	assert.False(t, bytes.Contains(raw, []byte(secret)), "открытый текст в файле")
	assert.False(t, bytes.Contains(raw, []byte("SQLite format 3")), "заголовок SQLite открыт")
	assert.False(t, bytes.Contains(raw, []byte("CREATE TABLE")), "схема открыта")

	db = openT(t, path, dek)
	var n int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM t WHERE s LIKE ?", secret+"%").Scan(&n))
	assert.Equal(t, 20, n)
	assert.Equal(t, "1", pragma(t, db, "auto_vacuum"), "сохранился после переоткрытия")
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	path := newFile(t, dir)
	db := openT(t, path, crypto.NewKey())
	fill(t, db, 3)
	require.NoError(t, db.Close())

	cases := []struct {
		Name    string
		Path    string
		DEK     []byte
		WantErr error
	}{
		{Name: "чужой DEK", Path: path, DEK: crypto.NewKey(), WantErr: errs.VaultCorrupt},
		{Name: "нет файла", Path: filepath.Join(dir, "none.pwv"), DEK: crypto.NewKey(), WantErr: errs.ObjectNotFound},
		{Name: "DEK не 32 байта", Path: path, DEK: []byte("short"), WantErr: errs.InvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			db, err := Open(context.Background(), tc.Path, tc.DEK)
			require.ErrorIs(t, err, tc.WantErr)
			assert.Nil(t, db)
		})
	}
	_, err := os.Stat(filepath.Join(dir, "none.pwv"))
	assert.True(t, errors.Is(err, os.ErrNotExist), "несуществующий файл не создан")
}

func TestCorruptPage(t *testing.T) {
	cases := []struct {
		Name string
		Off  int64
	}{
		{Name: "страница 1 (схема)", Off: HeaderOffset + 100},
		{Name: "страница 2 (данные)", Off: HeaderOffset + PageSize + 100},
		{Name: "последняя страница", Off: -100},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			path := newFile(t, t.TempDir())
			dek := crypto.NewKey()
			db := openT(t, path, dek)
			fill(t, db, 40)
			require.NoError(t, db.Close())

			f, err := os.OpenFile(path, os.O_RDWR, 0)
			require.NoError(t, err)
			off := tc.Off
			if off < 0 {
				st, err := f.Stat()
				require.NoError(t, err)
				off += st.Size()
			}
			_, err = f.WriteAt([]byte("испорчено"), off)
			require.NoError(t, err)
			require.NoError(t, f.Close())

			db, err = Open(context.Background(), path, dek)
			if err == nil {
				_ = db.Close()
			}
			require.ErrorIs(t, err, errs.VaultCorrupt)
		})
	}
}

func TestJournalEncrypted(t *testing.T) {
	ctx := context.Background()
	path := newFile(t, t.TempDir())
	db := openT(t, path, crypto.NewKey())
	fill(t, db, 5)

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "UPDATE t SET s = 'new'")
	require.NoError(t, err)

	journal, err := os.ReadFile(path + "-journal")
	require.NoError(t, err, "журнал отката должен существовать во время транзакции")
	assert.NotEmpty(t, journal)
	assert.False(t, bytes.Contains(journal, []byte(secret)), "старые страницы в журнале открыты")
	require.NoError(t, tx.Rollback())

	_, err = os.Stat(path + "-journal")
	assert.True(t, errors.Is(err, os.ErrNotExist), "journal_mode=DELETE: журнал удалён после транзакции")
}

func TestAutoVacuumFreesSpace(t *testing.T) {
	ctx := context.Background()
	path := newFile(t, t.TempDir())
	db := openT(t, path, crypto.NewKey())
	fill(t, db, 2000)
	full, err := os.Stat(path)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, "DELETE FROM t")
	require.NoError(t, err)
	empty, err := os.Stat(path)
	require.NoError(t, err)
	assert.Less(t, empty.Size(), full.Size()/10, "auto_vacuum FULL: файл уменьшился сразу (%d → %d)", full.Size(), empty.Size())
}

func TestUnusualPath(t *testing.T) {
	name := "Моя папка #1 ?a=b 'x' 100% &"
	if runtime.GOOS == "windows" {
		name = "Моя папка #1 a=b 'x' 100% &" // ? в именах Windows запрещён
	}
	dir := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	path := newFile(t, dir)
	dek := crypto.NewKey()
	db := openT(t, path, dek)
	fill(t, db, 1)
	require.NoError(t, db.Close())

	db = openT(t, path, dek)
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(), "SELECT count(*) FROM t").Scan(&n))
	assert.Equal(t, 1, n)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "лишних файлов (из-за кривого URI) нет")
}

func TestVacuumInto(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := newFile(t, dir)
	dek := crypto.NewKey()
	db := openT(t, path, dek)
	fill(t, db, 30)

	dst := filepath.Join(dir, "copy.pwv")
	require.NoError(t, VacuumInto(ctx, db, dst, dek))
	require.ErrorIs(t, VacuumInto(ctx, db, dst, dek), errs.VaultExists, "не перезаписывает")
	require.ErrorIs(t, VacuumInto(ctx, db, filepath.Join(dir, "x.pwv"), []byte("short")), errs.InvalidRequest)

	raw, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, HeaderOffset), raw[:HeaderOffset], "место заголовка в копии пустое")
	assert.False(t, bytes.Contains(raw, []byte(secret)), "копия открыта")
	if st, err := os.Stat(dst); assert.NoError(t, err) && runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	cp := openT(t, dst, dek)
	var n int
	require.NoError(t, cp.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n))
	assert.Equal(t, 30, n)
	assert.Equal(t, "1", pragma(t, cp, "auto_vacuum"), "auto_vacuum копии")

	_, err = Open(ctx, dst, crypto.NewKey())
	require.ErrorIs(t, err, errs.VaultCorrupt, "чужой DEK не открывает копию")
}

func TestTx(t *testing.T) {
	ctx := context.Background()
	db := openT(t, newFile(t, t.TempDir()), crypto.NewKey())
	fill(t, db, 0)
	m := NewTxManager(func() (*sql.DB, error) { return db, nil })
	count := func() int {
		var n int
		require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n))
		return n
	}
	insert := func(ctx context.Context) error {
		q, err := m.Q(ctx)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, "INSERT INTO t (s) VALUES ('x')")
		return err
	}
	boom := errors.New("boom")

	// ---- коммит ----
	require.NoError(t, m.Do(ctx, func(ctx context.Context) error { return insert(ctx) }))
	assert.Equal(t, 1, count())

	// ---- ошибка — откат ----
	err := m.Do(ctx, func(ctx context.Context) error {
		require.NoError(t, insert(ctx))
		return boom
	})
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, count())

	// ---- паника — откат и паника дальше ----
	assert.PanicsWithValue(t, "panic!", func() {
		_ = m.Do(ctx, func(ctx context.Context) error {
			require.NoError(t, insert(ctx))
			panic("panic!")
		})
	})
	assert.Equal(t, 1, count())

	// ---- вложенный Do — та же транзакция: ошибка внешнего откатывает и внутренний ----
	err = m.Do(ctx, func(ctx context.Context) error {
		require.NoError(t, m.Do(ctx, func(ctx context.Context) error { return insert(ctx) }))
		return boom
	})
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, count())

	// ---- Q без транзакции — сама база ----
	q, err := m.Q(ctx)
	require.NoError(t, err)
	assert.Same(t, db, q)

	// ---- база не открыта ----
	closed := NewTxManager(func() (*sql.DB, error) { return nil, errs.VaultNotOpen })
	require.ErrorIs(t, closed.Do(ctx, func(context.Context) error { return nil }), errs.VaultNotOpen)
}

func migrations(sqls ...string) []Migration {
	list := make([]Migration, len(sqls))
	for i, s := range sqls {
		list[i] = Migration{Version: i + 1, Name: "m", SQL: s}
	}
	return list
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	db := openT(t, newFile(t, t.TempDir()), crypto.NewKey())
	v2 := migrations(
		"CREATE TABLE a (id INTEGER PRIMARY KEY);",
		"CREATE TABLE b (id INTEGER PRIMARY KEY); INSERT INTO b VALUES (1);",
	)
	version := func() int {
		v, err := Version(ctx, db)
		require.NoError(t, err)
		return v
	}

	n, err := Pending(ctx, db, v2)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	require.NoError(t, Migrate(ctx, db, v2))
	assert.Equal(t, 2, version())
	require.NoError(t, Migrate(ctx, db, v2), "повтор — ничего не делает")
	assert.Equal(t, 2, version())

	// ---- упавшая миграция — откат целиком ----
	bad := append(v2, migrations("", "", "CREATE TABLE c (id INTEGER); INSERT INTO nope VALUES (1);")[2])
	require.Error(t, Migrate(ctx, db, bad))
	assert.Equal(t, 2, version())
	var c int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name = 'c'").Scan(&c))
	assert.Zero(t, c, "таблица c из упавшей миграции откатилась")

	// ---- база новее программы ----
	require.ErrorIs(t, Migrate(ctx, db, v2[:1]), errs.VaultTooNew)
	_, err = Pending(ctx, db, v2[:1])
	require.ErrorIs(t, err, errs.VaultTooNew)
	assert.Equal(t, 2, version(), "не тронута")
}

func TestLoadMigrations(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	cases := []struct {
		Name    string
		FS      fstest.MapFS
		Want    []int
		WantErr bool
	}{
		{Name: "по порядку", FS: fstest.MapFS{"m/002_b.sql": file("B"), "m/001_a.sql": file("A"), "m/README.md": file("x")}, Want: []int{1, 2}},
		{Name: "пусто", FS: fstest.MapFS{"m/README.md": file("x")}, Want: nil},
		{Name: "пропуск номера", FS: fstest.MapFS{"m/001_a.sql": file("A"), "m/003_c.sql": file("C")}, WantErr: true},
		{Name: "повтор номера", FS: fstest.MapFS{"m/001_a.sql": file("A"), "m/001_b.sql": file("B")}, WantErr: true},
		{Name: "не с 1", FS: fstest.MapFS{"m/002_b.sql": file("B")}, WantErr: true},
		{Name: "кривое имя", FS: fstest.MapFS{"m/1_a.sql": file("A")}, WantErr: true},
		{Name: "заглавные в имени", FS: fstest.MapFS{"m/001_Init.sql": file("A")}, WantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			list, err := LoadMigrations(tc.FS, "m")
			if tc.WantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var got []int
			for _, m := range list {
				got = append(got, m.Version)
			}
			assert.Equal(t, tc.Want, got)
		})
	}

	embedded, err := Migrations()
	require.NoError(t, err, "вшитые миграции программы читаются")
	assert.Empty(t, embedded, "этап 2: миграций ещё нет (схема — этап 3)")
}

func TestFileURI(t *testing.T) {
	q := map[string][]string{"vfs": {VFSName}, "mode": {"rw"}}
	cases := []struct {
		Name string
		Path string
		Want string
	}{
		{Name: "unix: пробел и спецсимволы", Path: "/tmp/a b/v?#'.pwv", Want: "file:/tmp/a%20b/v%3F%23%27.pwv?mode=rw&vfs=brassbox"},
		// Путь Windows — родной (без «/» в начале): VFS ncruces отдаёт его в os.OpenFile как есть.
		{Name: "windows: диск без ведущего /", Path: `C:\Users\a b\v.pwv`, Want: "file:C:%5CUsers%5Ca%20b%5Cv.pwv?mode=rw&vfs=brassbox"},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			assert.Equal(t, tc.Want, fileURI(tc.Path, q))
		})
	}
}
