// Package config — пути к данным и режим отладки.
// Данные: macOS ~/Library/Application Support/Brassbox, Windows %AppData%\Brassbox.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"brassbox/internal/constant"
)

// Config — пути к данным программы и режим отладки.
type Config struct {
	Debug bool

	DataDir      string // корень данных
	VaultsDir    string // базы *.pwv
	KeysDir      string // ключи чужих баз *.key
	BackupsDir   string // автокопии
	LogsDir      string // brassbox.log + ротация
	SettingsFile string // settings.json
}

// Load собирает пути и создаёт папки (0700 — только владелец).
func Load() (Config, error) {
	root := os.Getenv(constant.DataDirEnv)
	if root == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Config{}, fmt.Errorf("os.UserConfigDir: %w", err)
		}
		root = filepath.Join(base, constant.AppName)
	}

	c := Config{
		Debug:        os.Getenv(constant.DebugEnv) == "1",
		DataDir:      root,
		VaultsDir:    filepath.Join(root, "vaults"),
		KeysDir:      filepath.Join(root, "keys"),
		BackupsDir:   filepath.Join(root, "backups"),
		LogsDir:      filepath.Join(root, "logs"),
		SettingsFile: filepath.Join(root, "settings.json"),
	}

	for _, dir := range []string{c.DataDir, c.VaultsDir, c.KeysDir, c.BackupsDir, c.LogsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Config{}, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	return c, nil
}
