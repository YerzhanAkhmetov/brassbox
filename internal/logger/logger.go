// Package logger — текстовый slog в logs/brassbox.log с ротацией 1 МБ × 5 файлов.
package logger

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// FileName — имя файла журнала в папке logs.
	FileName   = "brassbox.log"
	maxSizeMB  = 1
	maxBackups = 4 // + текущий = 5 файлов
)

// New создаёт логгер. debug: уровень Debug и копия в консоль.
// Закрыть io.Closer при выходе из программы.
func New(dir string, debug bool) (*slog.Logger, io.Closer) {
	file := &lumberjack.Logger{
		Filename:   filepath.Join(dir, FileName),
		MaxSize:    maxSizeMB,
		MaxBackups: maxBackups,
		LocalTime:  true,
	}

	level := slog.LevelInfo
	var w io.Writer = file
	if debug {
		level = slog.LevelDebug
		w = io.MultiWriter(file, os.Stderr)
	}

	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), file
}
