package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"brassbox/internal/constant"
)

func TestLoadCreatesDirs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	t.Setenv(constant.DataDirEnv, root)

	c, err := Load()
	require.NoError(t, err)

	assert.Equal(t, root, c.DataDir)
	assert.Equal(t, filepath.Join(root, "settings.json"), c.SettingsFile)
	for _, dir := range []string{c.DataDir, c.VaultsDir, c.KeysDir, c.BackupsDir, c.LogsDir} {
		st, err := os.Stat(dir)
		require.NoError(t, err, dir)
		assert.True(t, st.IsDir(), dir)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o700), st.Mode().Perm(), "права %s", dir)
		}
	}

	// Повторный вызов — без ошибок, папки уже есть.
	_, err = Load()
	require.NoError(t, err)
}

func TestLoadDebug(t *testing.T) {
	cases := []struct {
		Name string
		Env  string
		Want bool
	}{
		{"не задано", "", false},
		{"1", "1", true},
		{"true — не считается", "true", false},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Setenv(constant.DataDirEnv, t.TempDir())
			t.Setenv(constant.DebugEnv, c.Env)
			conf, err := Load()
			require.NoError(t, err)
			assert.Equal(t, c.Want, conf.Debug)
		})
	}
}

func TestLoadDefaultDir(t *testing.T) {
	// Без переопределения — системная папка конфигов + Brassbox. Подменяем HOME, чтобы не писать в настоящую.
	if runtime.GOOS == "windows" {
		t.Setenv("AppData", t.TempDir())
	} else {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("XDG_CONFIG_HOME", "")
	}
	t.Setenv(constant.DataDirEnv, "")

	c, err := Load()
	require.NoError(t, err)
	base, err := os.UserConfigDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, constant.AppName), c.DataDir)
}

func TestLoadUnwritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("права папок на Windows — по-другому")
	}
	ro := t.TempDir()
	require.NoError(t, os.Chmod(ro, 0o500))
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	t.Setenv(constant.DataDirEnv, filepath.Join(ro, "data"))

	_, err := Load()
	require.Error(t, err)
}
