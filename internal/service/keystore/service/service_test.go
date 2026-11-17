package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
	"brassbox/internal/service/keystore"
	localConstant "brassbox/internal/service/keystore/service/constant"
)

var _ keystore.Keystore = (*Service)(nil)

// fakeProtector — вместо Keychain / DPAPI: шифрует своим ключом («другой компьютер» = другой ключ).
type fakeProtector struct{ k []byte }

func newFake() fakeProtector { return fakeProtector{crypto.NewKey()} }

func (p fakeProtector) Protect(b []byte) ([]byte, error)   { return crypto.Seal(p.k, b, nil) }
func (p fakeProtector) Unprotect(b []byte) ([]byte, error) { return crypto.Open(p.k, b, nil) }

// brokenProtector — система отказала (Keychain заблокирован и т.п.).
type brokenProtector struct{}

func (brokenProtector) Protect([]byte) ([]byte, error)   { return nil, errors.New("os says no") }
func (brokenProtector) Unprotect([]byte) ([]byte, error) { return nil, errors.New("os says no") }

var fastKDF = crypto.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

func newSvc(t *testing.T, p Protector) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys", "master.key")
	return New(path, p, WithKDF(fastKDF)), path
}

func TestCreateLoad(t *testing.T) {
	s, path := newSvc(t, newFake())

	assert.False(t, s.Exists())
	_, err := s.Load()
	require.ErrorIs(t, err, errs.KeyNotFound)

	key, err := s.Create()
	require.NoError(t, err)
	require.Len(t, key, crypto.KeySize)
	assert.True(t, s.Exists())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(raw, key), "ключ лежит в файле в открытом виде")
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	got, err := s.Load()
	require.NoError(t, err)
	assert.Equal(t, key, got)

	_, err = s.Create()
	require.ErrorIs(t, err, errs.KeyExists, "второй Create")
	again, err := s.Load()
	require.NoError(t, err)
	assert.Equal(t, key, again, "второй Create не изменил ключ")

	left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".key-*"))
	assert.Empty(t, left, "временные файлы")
}

func TestCreateConcurrent(t *testing.T) {
	s, _ := newSvc(t, newFake())
	const n = 8
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		keys [][]byte
		errN int
	)
	for range n {
		wg.Go(func() {
			k, err := s.Create()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				assert.ErrorIs(t, err, errs.KeyExists)
				errN++
				return
			}
			keys = append(keys, k)
		})
	}
	wg.Wait()
	require.Len(t, keys, 1, "создаться должен ровно один ключ")
	assert.Equal(t, n-1, errN)
	got, err := s.Load()
	require.NoError(t, err)
	assert.Equal(t, keys[0], got)
}

func TestLoadUnreadable(t *testing.T) {
	cases := []struct {
		Name  string
		Setup func(t *testing.T, path string) Protector
	}{
		{Name: "другой компьютер", Setup: func(t *testing.T, path string) Protector {
			_, err := New(path, newFake()).Create()
			require.NoError(t, err)
			return newFake()
		}},
		{Name: "система отказала", Setup: func(t *testing.T, path string) Protector {
			_, err := New(path, newFake()).Create()
			require.NoError(t, err)
			return brokenProtector{}
		}},
		{Name: "мусор без магии", Setup: func(t *testing.T, path string) Protector {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte("not a key"), 0o600))
			return newFake()
		}},
		{Name: "магия и обрезанный blob", Setup: func(t *testing.T, path string) Protector {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, []byte(localConstant.MasterMagic+"xx"), 0o600))
			return newFake()
		}},
		{Name: "пустой файл", Setup: func(t *testing.T, path string) Protector {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, nil, 0o600))
			return newFake()
		}},
		{Name: "внутри не 32 байта", Setup: func(t *testing.T, path string) Protector {
			p := newFake()
			blob, err := p.Protect([]byte("short"))
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
			require.NoError(t, os.WriteFile(path, append([]byte(localConstant.MasterMagic), blob...), 0o600))
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			p := tc.Setup(t, path)
			_, err := New(path, p).Load()
			require.ErrorIs(t, err, errs.KeyUnreadable)
		})
	}
}

func TestCreateProtectFails(t *testing.T) {
	s, path := newSvc(t, brokenProtector{})
	_, err := s.Create()
	require.Error(t, err)
	assert.NoFileExists(t, path)
}

func TestStore(t *testing.T) {
	t.Run("ключа нет — сохраняет", func(t *testing.T) {
		s, _ := newSvc(t, newFake())
		key := crypto.NewKey()
		require.NoError(t, s.Store(key))
		got, err := s.Load()
		require.NoError(t, err)
		assert.Equal(t, key, got)
	})
	t.Run("рабочий ключ не заменяет", func(t *testing.T) {
		s, _ := newSvc(t, newFake())
		own, err := s.Create()
		require.NoError(t, err)
		require.ErrorIs(t, s.Store(crypto.NewKey()), errs.KeyExists)
		got, err := s.Load()
		require.NoError(t, err)
		assert.Equal(t, own, got)
	})
	t.Run("нечитаемый — переименован, новый сохранён", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "master.key")
		_, err := New(path, newFake()).Create()
		require.NoError(t, err)
		old, err := os.ReadFile(path)
		require.NoError(t, err)

		s := New(path, newFake()) // «после переустановки системы»
		key := crypto.NewKey()
		require.NoError(t, s.Store(key))
		got, err := s.Load()
		require.NoError(t, err)
		assert.Equal(t, key, got)

		kept, err := os.ReadFile(path + localConstant.UnreadableSuffix)
		require.NoError(t, err, "старый файл не удалён")
		assert.Equal(t, old, kept)
	})
	t.Run("не 32 байта", func(t *testing.T) {
		s, _ := newSvc(t, newFake())
		require.ErrorIs(t, s.Store([]byte("short")), errs.InvalidRequest)
	})
}

func TestPVKeyRoundTrip(t *testing.T) {
	s, _ := newSvc(t, newFake())
	key := crypto.NewKey()

	cases := []struct {
		Name      string
		Password  string
		NeedsPass bool
	}{
		{Name: "без пароля", Password: "", NeedsPass: false},
		{Name: "с паролем", Password: "ветер-кофе-42", NeedsPass: true},
		{Name: "пароль ровно 6 символов кириллицей", Password: "пароль", NeedsPass: true},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			data, err := s.ExportPVKey(key, tc.Password)
			require.NoError(t, err)
			assert.Contains(t, string(data), crypto.Fingerprint(key))
			if tc.NeedsPass {
				assert.False(t, bytes.Contains(data, key), "ключ в открытом виде")
			}

			needs, err := s.PVKeyNeedsPassword(data)
			require.NoError(t, err)
			assert.Equal(t, tc.NeedsPass, needs)

			got, err := s.ImportPVKey(data, tc.Password)
			require.NoError(t, err)
			assert.Equal(t, key, got)
		})
	}
}

func TestPVKeyImportErrors(t *testing.T) {
	s, _ := newSvc(t, newFake())
	key := crypto.NewKey()
	withPass, err := s.ExportPVKey(key, "secret-123")
	require.NoError(t, err)
	plain, err := s.ExportPVKey(key, "")
	require.NoError(t, err)

	replace := func(data []byte, old, repl string) []byte {
		out := bytes.Replace(data, []byte(old), []byte(repl), 1)
		require.NotEqual(t, data, out, "замена %q не сработала", old)
		return out
	}

	cases := []struct {
		Name     string
		Data     []byte
		Password string
		WantErr  error
	}{
		// ---- пароль ----
		{Name: "неверный пароль", Data: withPass, Password: "secret-124", WantErr: errs.PasswordWrong},
		{Name: "пустой пароль у файла с паролем", Data: withPass, Password: "", WantErr: errs.PasswordWrong},
		// ---- не наш / испорченный файл ----
		{Name: "пусто", Data: nil, WantErr: errs.PVKeyInvalid},
		{Name: "не JSON", Data: []byte("hello"), WantErr: errs.PVKeyInvalid},
		{Name: "чужой формат", Data: replace(plain, `"brassbox-pvkey"`, `"other"`), WantErr: errs.PVKeyInvalid},
		{Name: "версия 2", Data: replace(plain, `"version": 1`, `"version": 2`), WantErr: errs.PVKeyInvalid},
		{Name: "отпечаток не тот (без пароля)", Data: replace(plain, crypto.Fingerprint(key), "0000-0000-0000-0000"), WantErr: errs.PVKeyInvalid},
		{Name: "отпечаток не тот (с паролем, AAD)", Data: replace(withPass, crypto.Fingerprint(key), "0000-0000-0000-0000"), Password: "secret-123", WantErr: errs.PasswordWrong},
		{Name: "чужой алгоритм", Data: replace(withPass, `"argon2id"`, `"md5"`), Password: "secret-123", WantErr: errs.PVKeyInvalid},
		{Name: "память 100 ГиБ", Data: replace(withPass, `"m": 64`, `"m": 104857600`), Password: "secret-123", WantErr: errs.PVKeyInvalid},
		{Name: "и key, и sealed", Data: []byte(`{"format":"brassbox-pvkey","version":1,"fingerprint":"x","key":"AAAA","sealed":"AAAA","kdf":{"alg":"argon2id"}}`), WantErr: errs.PVKeyInvalid},
		{Name: "ни key, ни sealed", Data: []byte(`{"format":"brassbox-pvkey","version":1,"fingerprint":"x"}`), WantErr: errs.PVKeyInvalid},
		{Name: "больше 64 КиБ", Data: append(bytes.Clone(plain), bytes.Repeat([]byte(" "), 64<<10)...), WantErr: errs.PVKeyInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := s.ImportPVKey(tc.Data, tc.Password)
			require.ErrorIs(t, err, tc.WantErr)
			assert.Nil(t, got)
		})
	}
}

func TestPVKeyExportErrors(t *testing.T) {
	s, _ := newSvc(t, newFake())
	_, err := s.ExportPVKey(crypto.NewKey(), "12345")
	require.ErrorIs(t, err, errs.PasswordTooShort, "5 символов")
	_, err = s.ExportPVKey(crypto.NewKey(), "пятьб")
	require.ErrorIs(t, err, errs.PasswordTooShort, "5 символов кириллицей (10 байт)")
	_, err = s.ExportPVKey([]byte("short"), "")
	require.ErrorIs(t, err, errs.InvalidRequest)
}

func TestPVKeySaltUnique(t *testing.T) {
	s, _ := newSvc(t, newFake())
	key := crypto.NewKey()
	a, err := s.ExportPVKey(key, "secret-123")
	require.NoError(t, err)
	b, err := s.ExportPVKey(key, "secret-123")
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "соль и nonce каждый раз новые")
}
