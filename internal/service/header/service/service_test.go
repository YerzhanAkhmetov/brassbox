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
	"brassbox/internal/service/header"
	headerModel "brassbox/internal/service/header/model"
	localConstant "brassbox/internal/service/header/service/constant"
	localModel "brassbox/internal/service/header/service/model"
)

var _ header.Header = (*Service)(nil)

var fastKDF = crypto.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}

const pass = "верный-пароль-1"

type vault struct {
	svc    *Service
	path   string
	dek    []byte
	master []byte
}

func newVault(t *testing.T, password string) vault {
	t.Helper()
	v := vault{
		svc:    New(WithKDF(fastKDF)),
		path:   filepath.Join(t.TempDir(), "vault.pwv"),
		dek:    crypto.NewKey(),
		master: crypto.NewKey(),
	}
	require.NoError(t, v.svc.Create(v.path, v.dek, v.master, password))
	return v
}

func (v vault) info(t *testing.T) headerModel.Info {
	t.Helper()
	i, err := v.svc.Read(v.path)
	require.NoError(t, err)
	return i
}

// raw — живая копия заголовка (для проверок и подделок в тестах).
func (v vault) raw(t *testing.T) state {
	t.Helper()
	f, err := os.Open(v.path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	st, err := readState(f)
	require.NoError(t, err)
	return st
}

// put — записать подделанный заголовок следующей копией.
func (v vault) put(t *testing.T, change func(h *localModel.Header)) {
	t.Helper()
	st := v.raw(t)
	change(&st.h)
	f, err := os.OpenFile(v.path, os.O_RDWR, 0)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, writeNext(f, &st))
}

func TestCreateRead(t *testing.T) {
	cases := []struct {
		Name     string
		Password string
		HasPass  bool
	}{
		{Name: "без пароля", Password: "", HasPass: false},
		{Name: "с паролем", Password: pass, HasPass: true},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			v := newVault(t, tc.Password)

			raw, err := os.ReadFile(v.path)
			require.NoError(t, err)
			assert.Len(t, raw, localConstant.Size)
			assert.True(t, bytes.HasPrefix(raw, []byte(localConstant.Magic)))
			assert.False(t, bytes.Contains(raw, v.dek), "DEK открыто в файле")
			assert.False(t, bytes.Contains(raw, v.master), "мастер-ключ открыто в файле")
			if runtime.GOOS != "windows" {
				st, err := os.Stat(v.path)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
			}

			i := v.info(t)
			assert.Len(t, i.VaultID, localConstant.VaultIDSize)
			assert.Equal(t, tc.HasPass, i.HasPassword)
			assert.False(t, i.Locked)
			assert.Equal(t, 0, i.Fails)
			assert.Equal(t, localConstant.MaxFails, i.Left)

			dek, err := v.svc.UnlockMaster(v.path, v.master)
			require.NoError(t, err)
			assert.Equal(t, v.dek, dek)
		})
	}
}

func TestCreateErrors(t *testing.T) {
	v := newVault(t, "")
	dir := t.TempDir()
	cases := []struct {
		Name     string
		Path     string
		DEK      []byte
		Master   []byte
		Password string
		WantErr  error
	}{
		{Name: "файл уже есть", Path: v.path, DEK: crypto.NewKey(), Master: crypto.NewKey(), WantErr: errs.VaultExists},
		{Name: "пароль 7 символов", Path: filepath.Join(dir, "a.pwv"), DEK: crypto.NewKey(), Master: crypto.NewKey(), Password: "1234567", WantErr: errs.PasswordTooShort},
		{Name: "DEK не 32 байта", Path: filepath.Join(dir, "b.pwv"), DEK: []byte("x"), Master: crypto.NewKey(), WantErr: errs.InvalidRequest},
		{Name: "мастер-ключ не 32 байта", Path: filepath.Join(dir, "c.pwv"), DEK: crypto.NewKey(), Master: nil, WantErr: errs.InvalidRequest},
	}
	before, err := os.ReadFile(v.path)
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			err := v.svc.Create(tc.Path, tc.DEK, tc.Master, tc.Password)
			require.ErrorIs(t, err, tc.WantErr)
			if tc.Path != v.path {
				assert.NoFileExists(t, tc.Path)
			}
		})
	}
	after, err := os.ReadFile(v.path)
	require.NoError(t, err)
	assert.Equal(t, before, after, "существующий файл не тронут")
}

func TestUnlockMaster(t *testing.T) {
	v := newVault(t, pass)
	_, err := v.svc.UnlockMaster(v.path, crypto.NewKey())
	require.ErrorIs(t, err, errs.KeyWrong, "чужой ключ")
	_, err = v.svc.UnlockMaster(v.path, []byte("short"))
	require.ErrorIs(t, err, errs.KeyWrong, "кривой ключ")
	assert.Equal(t, 0, v.info(t).Fails, "мастер-ключ не трогает счётчик")
}

func TestUnlockPassword(t *testing.T) {
	v := newVault(t, pass)
	dek, err := v.svc.UnlockPassword(v.path, pass)
	require.NoError(t, err)
	assert.Equal(t, v.dek, dek)

	noPass := newVault(t, "")
	_, err = noPass.svc.UnlockPassword(noPass.path, pass)
	require.ErrorIs(t, err, errs.PasswordNotSet)
}

func TestWrongPasswordCounter(t *testing.T) {
	v := newVault(t, pass)

	// ---- 4 неверных: осталось 4, 3, 2, 1 ----
	for i := 1; i < localConstant.MaxFails; i++ {
		_, err := v.svc.UnlockPassword(v.path, "неверный-пароль")
		require.ErrorIs(t, err, errs.PasswordWrong)
		var wp headerModel.WrongPasswordError
		require.True(t, errors.As(err, &wp))
		assert.Equal(t, localConstant.MaxFails-i, wp.Left)
		assert.Equal(t, i, v.info(t).Fails)
	}

	// ---- верный сбрасывает счётчик ----
	_, err := v.svc.UnlockPassword(v.path, pass)
	require.NoError(t, err)
	assert.Equal(t, 0, v.info(t).Fails)

	// ---- пустой ввод — не попытка ----
	_, err = v.svc.UnlockPassword(v.path, "")
	require.ErrorIs(t, err, errs.PasswordWrong)
	assert.Equal(t, 0, v.info(t).Fails)

	// ---- 5 неверных → замок 1 стёрт ----
	for i := 1; i < localConstant.MaxFails; i++ {
		_, err = v.svc.UnlockPassword(v.path, "неверный-пароль")
		require.ErrorIs(t, err, errs.PasswordWrong)
	}
	_, err = v.svc.UnlockPassword(v.path, "неверный-пароль")
	require.ErrorIs(t, err, errs.PasswordLocked, "5-я попытка")

	i := v.info(t)
	assert.True(t, i.Locked)
	assert.False(t, i.HasPassword)
	assert.Equal(t, 0, i.Left)
	assert.Nil(t, v.raw(t).h.Password, "замка 1 нет в живой копии")

	_, err = v.svc.UnlockPassword(v.path, pass)
	require.ErrorIs(t, err, errs.PasswordLocked, "верный пароль больше не открывает")

	// ---- мастер-ключ открывает, новый пароль — замок заново ----
	dek, err := v.svc.UnlockMaster(v.path, v.master)
	require.NoError(t, err)
	require.NoError(t, v.svc.SetPassword(v.path, dek, "новый-пароль-2"))
	i = v.info(t)
	assert.True(t, i.HasPassword)
	assert.False(t, i.Locked)
	assert.Equal(t, 0, i.Fails)
	got, err := v.svc.UnlockPassword(v.path, "новый-пароль-2")
	require.NoError(t, err)
	assert.Equal(t, v.dek, got)
}

func TestCounterWrittenBeforeCheck(t *testing.T) {
	v := newVault(t, pass)
	// Испорченные параметры Argon2id → проверка пароля падает с ошибкой,
	// но попытка уже записана (как если бы программу убили во время Argon2id).
	v.put(t, func(h *localModel.Header) { h.Password.Threads = 0 })

	_, err := v.svc.UnlockPassword(v.path, pass)
	require.ErrorIs(t, err, errs.VaultDamaged)
	assert.Equal(t, 1, v.info(t).Fails)
}

func TestConcurrentWrongPasswords(t *testing.T) {
	v := newVault(t, pass)
	const n = 12
	var (
		wg               sync.WaitGroup
		mu               sync.Mutex
		wrong, locked, x int
	)
	for range n {
		wg.Go(func() {
			_, err := v.svc.UnlockPassword(v.path, "неверный-пароль")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, errs.PasswordLocked):
				locked++
			case errors.Is(err, errs.PasswordWrong):
				wrong++
			default:
				x++
			}
		})
	}
	wg.Wait()
	assert.Equal(t, localConstant.MaxFails-1, wrong)
	assert.Equal(t, n-localConstant.MaxFails+1, locked)
	assert.Equal(t, 0, x)
	assert.True(t, v.info(t).Locked)
}

func TestSetRemovePassword(t *testing.T) {
	v := newVault(t, "")

	require.ErrorIs(t, v.svc.SetPassword(v.path, v.dek, "1234567"), errs.PasswordTooShort)
	require.ErrorIs(t, v.svc.SetPassword(v.path, crypto.NewKey(), pass), errs.KeyWrong, "чужой DEK")
	assert.False(t, v.info(t).HasPassword)

	require.NoError(t, v.svc.SetPassword(v.path, v.dek, "пароль8!"), "ровно 8 символов кириллицей")
	_, err := v.svc.UnlockPassword(v.path, "пароль8!")
	require.NoError(t, err)

	require.NoError(t, v.svc.SetPassword(v.path, v.dek, pass), "смена пароля")
	_, err = v.svc.UnlockPassword(v.path, "пароль8!")
	require.ErrorIs(t, err, errs.PasswordWrong, "старый пароль не подходит")
	_, err = v.svc.UnlockPassword(v.path, pass)
	require.NoError(t, err)

	require.ErrorIs(t, v.svc.RemovePassword(v.path, crypto.NewKey()), errs.KeyWrong)
	require.NoError(t, v.svc.RemovePassword(v.path, v.dek))
	_, err = v.svc.UnlockPassword(v.path, pass)
	require.ErrorIs(t, err, errs.PasswordNotSet)
	dek, err := v.svc.UnlockMaster(v.path, v.master)
	require.NoError(t, err)
	assert.Equal(t, v.dek, dek)
}

func TestRewrapMaster(t *testing.T) {
	v := newVault(t, pass)
	mine := crypto.NewKey()

	require.ErrorIs(t, v.svc.RewrapMaster(v.path, crypto.NewKey(), mine), errs.KeyWrong, "чужой DEK")
	require.NoError(t, v.svc.RewrapMaster(v.path, v.dek, mine))

	_, err := v.svc.UnlockMaster(v.path, v.master)
	require.ErrorIs(t, err, errs.KeyWrong, "старый ключ больше не открывает")
	dek, err := v.svc.UnlockMaster(v.path, mine)
	require.NoError(t, err)
	assert.Equal(t, v.dek, dek)
	_, err = v.svc.UnlockPassword(v.path, pass)
	require.NoError(t, err, "пароль не задет")
}

func TestLocksBoundToVault(t *testing.T) {
	a, b := newVault(t, pass), newVault(t, pass)
	// Тот же DEK и ключ в двух файлах — замок из A не открывается в B (AAD = id хранилища).
	b.dek, b.master = a.dek, a.master
	require.NoError(t, os.Remove(b.path))
	require.NoError(t, b.svc.Create(b.path, b.dek, b.master, pass))

	aLock := a.raw(t).h
	b.put(t, func(h *localModel.Header) {
		h.Master = aLock.Master
		h.Password = aLock.Password
	})
	_, err := b.svc.UnlockMaster(b.path, b.master)
	require.ErrorIs(t, err, errs.KeyWrong)
	_, err = b.svc.UnlockPassword(b.path, pass)
	require.ErrorIs(t, err, errs.PasswordWrong)

	// Замок 2 на место замка 1 — тоже не открывается.
	v := newVault(t, pass)
	v.put(t, func(h *localModel.Header) { h.Password.Sealed = h.Master.Sealed })
	_, err = v.svc.UnlockPassword(v.path, pass)
	require.ErrorIs(t, err, errs.PasswordWrong)
}

func TestTornWrite(t *testing.T) {
	v := newVault(t, "")
	require.NoError(t, v.svc.SetPassword(v.path, v.dek, pass)) // Seq 2 → копия B
	live := v.raw(t)
	require.Equal(t, 1, live.slot)
	require.Equal(t, uint64(2), live.h.Seq)

	corrupt := func(off int64) {
		f, err := os.OpenFile(v.path, os.O_RDWR, 0)
		require.NoError(t, err)
		_, err = f.WriteAt([]byte("обрыв"), off)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}

	// ---- испорчена живая копия B → читается A (до смены пароля) ----
	corrupt(localConstant.SlotBOff + 20)
	i := v.info(t)
	assert.False(t, i.HasPassword, "откат к копии A")
	dek, err := v.svc.UnlockMaster(v.path, v.master)
	require.NoError(t, err)
	assert.Equal(t, v.dek, dek)

	// ---- следующая запись идёт в испорченную B, A цела ----
	require.NoError(t, v.svc.SetPassword(v.path, v.dek, pass))
	live = v.raw(t)
	assert.Equal(t, 1, live.slot)
	assert.Equal(t, uint64(2), live.h.Seq)

	// ---- обе испорчены ----
	corrupt(localConstant.SlotAOff + 20)
	corrupt(localConstant.SlotBOff + 20)
	_, err = v.svc.Read(v.path)
	require.ErrorIs(t, err, errs.VaultDamaged)
	_, err = v.svc.UnlockMaster(v.path, v.master)
	require.ErrorIs(t, err, errs.VaultDamaged)
}

func TestSlotsAlternate(t *testing.T) {
	v := newVault(t, pass)
	for i := range 6 {
		_, err := v.svc.UnlockPassword(v.path, pass) // 2 записи на попытку
		require.NoError(t, err)
		st := v.raw(t)
		assert.Equal(t, uint64(1+2*(i+1)), st.h.Seq)
		assert.Equal(t, 0, st.slot, "чётное число записей — снова A")
	}
}

func TestDataAfterHeaderUntouched(t *testing.T) {
	v := newVault(t, pass)
	tail := bytes.Repeat([]byte("SQLITE-PAGE-"), 1000)
	f, err := os.OpenFile(v.path, os.O_RDWR|os.O_APPEND, 0)
	require.NoError(t, err)
	_, err = f.Write(tail)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, _ = v.svc.UnlockPassword(v.path, "неверный-пароль")
	_, err = v.svc.UnlockPassword(v.path, pass)
	require.NoError(t, err)
	require.NoError(t, v.svc.SetPassword(v.path, v.dek, "другой-пароль"))
	require.NoError(t, v.svc.RewrapMaster(v.path, v.dek, crypto.NewKey()))
	require.NoError(t, v.svc.RemovePassword(v.path, v.dek))

	raw, err := os.ReadFile(v.path)
	require.NoError(t, err)
	require.Len(t, raw, localConstant.Size+len(tail))
	assert.Equal(t, tail, raw[localConstant.Size:], "данные после заголовка не тронуты")
}

func TestReadNotBrassbox(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	svc := New(WithKDF(fastKDF))
	cases := []struct {
		Name    string
		Path    string
		WantErr error
	}{
		{Name: "нет файла", Path: filepath.Join(dir, "none.pwv"), WantErr: errs.ObjectNotFound},
		{Name: "пустой", Path: write("empty.pwv", nil), WantErr: errs.VaultInvalid},
		{Name: "короче 4 КиБ", Path: write("short.pwv", []byte(localConstant.Magic)), WantErr: errs.VaultInvalid},
		{Name: "SQLite без заголовка", Path: write("sqlite.pwv", append([]byte("SQLite format 3\x00"), make([]byte, 8192)...)), WantErr: errs.VaultInvalid},
		{Name: "магия, копий нет", Path: write("nocopy.pwv", append([]byte(localConstant.Magic), make([]byte, localConstant.Size)...)), WantErr: errs.VaultDamaged},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := svc.Read(tc.Path)
			require.ErrorIs(t, err, tc.WantErr)
			_, err = svc.UnlockPassword(tc.Path, pass)
			require.ErrorIs(t, err, tc.WantErr)
			_, err = svc.UnlockMaster(tc.Path, crypto.NewKey())
			require.ErrorIs(t, err, tc.WantErr)
		})
	}
}

func TestVerify(t *testing.T) {
	v := newVault(t, pass)
	require.NoError(t, v.svc.Verify(v.path, v.dek))
	require.ErrorIs(t, v.svc.Verify(v.path, crypto.NewKey()), errs.KeyWrong)
	require.ErrorIs(t, v.svc.Verify(v.path, []byte("short")), errs.KeyWrong)
	require.ErrorIs(t, v.svc.Verify(filepath.Join(t.TempDir(), "none"), v.dek), errs.ObjectNotFound)
	assert.Equal(t, uint64(1), v.raw(t).h.Seq, "Verify ничего не пишет")
}

func TestClone(t *testing.T) {
	v := newVault(t, pass)
	_, _ = v.svc.UnlockPassword(v.path, "неверный-пароль") // в копию уходит и счётчик (заголовок как есть)

	dst := filepath.Join(t.TempDir(), "copy.pwv")
	tail := []byte("SQLITE-PAGES")
	require.NoError(t, os.WriteFile(dst, append(make([]byte, localConstant.Size), tail...), 0o600))
	require.NoError(t, v.svc.Clone(v.path, dst))

	src, err := os.ReadFile(v.path)
	require.NoError(t, err)
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, src[:localConstant.Size], got[:localConstant.Size])
	assert.Equal(t, tail, got[localConstant.Size:], "данные после заголовка не тронуты")

	dek, err := v.svc.UnlockMaster(dst, v.master)
	require.NoError(t, err)
	assert.Equal(t, v.dek, dek)

	require.ErrorIs(t, v.svc.Clone(v.path, filepath.Join(t.TempDir(), "none")), errs.ObjectNotFound, "dst не создаётся")
	notBB := filepath.Join(t.TempDir(), "x.pwv")
	require.NoError(t, os.WriteFile(notBB, make([]byte, localConstant.Size), 0o600))
	require.ErrorIs(t, v.svc.Clone(notBB, dst), errs.VaultInvalid, "источник — не Brassbox")
}

func TestDecodeSlotRejects(t *testing.T) {
	v := newVault(t, pass)
	good := v.raw(t).h
	cases := []struct {
		Name   string
		Change func(h *localModel.Header)
	}{
		{Name: "чужая версия", Change: func(h *localModel.Header) { h.Format = 2 }},
		{Name: "id не 16 байт", Change: func(h *localModel.Header) { h.VaultID = h.VaultID[:8] }},
		{Name: "нет проверки DEK", Change: func(h *localModel.Header) { h.DEKCheck = nil }},
		{Name: "нет замка 2", Change: func(h *localModel.Header) { h.Master = nil }},
		{Name: "замок 1 без соли", Change: func(h *localModel.Header) { h.Password.Salt = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			h := good
			pw := *good.Password
			h.Password = &pw
			tc.Change(&h)
			b, err := encodeSlot(h, localConstant.SlotASize)
			require.NoError(t, err)
			_, ok := decodeSlot(b)
			assert.False(t, ok)
		})
	}
	b, err := encodeSlot(good, localConstant.SlotASize)
	require.NoError(t, err)
	_, ok := decodeSlot(b)
	assert.True(t, ok, "контроль: неизменённая копия читается")
}
