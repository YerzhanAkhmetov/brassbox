package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLevels(t *testing.T) {
	cases := []struct {
		Name      string
		Debug     bool
		WantDebug bool
	}{
		{"обычный режим — без Debug", false, false},
		{"отладка — с Debug", true, true},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			dir := t.TempDir()
			log, closer := New(dir, c.Debug)
			log.Debug("dbg-line")
			log.Info("info-line", "k", "v")
			require.NoError(t, closer.Close())

			b, err := os.ReadFile(filepath.Join(dir, FileName))
			require.NoError(t, err)
			s := string(b)
			assert.Contains(t, s, "info-line")
			assert.Contains(t, s, "k=v", "текстовый формат")
			assert.Equal(t, c.WantDebug, strings.Contains(s, "dbg-line"))
		})
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	log, closer := New(dir, false)
	line := strings.Repeat("x", 1000)
	for range 8 * 1100 { // ~8 МБ → должно остаться 5 файлов
		log.Info(line)
	}
	require.NoError(t, closer.Close())

	files, err := filepath.Glob(filepath.Join(dir, "brassbox*.log"))
	require.NoError(t, err)
	// lumberjack чистит старые копии в фоне — допускаем небольшую задержку через Eventually.
	assert.Eventually(t, func() bool {
		files, _ = filepath.Glob(filepath.Join(dir, "brassbox*.log"))
		return len(files) == maxBackups+1
	}, 2e9, 5e7, "файлов: %d", len(files))

	for _, f := range files {
		st, err := os.Stat(f)
		require.NoError(t, err)
		assert.LessOrEqual(t, st.Size(), int64(maxSizeMB<<20), f)
	}
}
