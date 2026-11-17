// Package app — сборка программы: конфиг → логи → обработчики → окно Wails.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	wailsapp "github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"brassbox/internal/config"
	"brassbox/internal/constant"
	handlerWails "brassbox/internal/handler/wails"
	"brassbox/internal/logger"
)

// Run запускает программу и возвращает код выхода.
func Run(assets fs.FS) int {
	conf, err := config.Load()
	if err != nil {
		// Логов ещё нет — пишем в консоль.
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}

	log, logCloser := logger.New(conf.LogsDir, conf.Debug)
	defer func() { _ = logCloser.Close() }()
	slog.SetDefault(log)
	slog.Info("start", "version", constant.Version, "data", conf.DataDir)

	handler := handlerWails.New()

	var ctx context.Context
	err = wailsapp.Run(&options.App{
		Title:            constant.AppName,
		Width:            1200,
		Height:           800,
		MinWidth:         900,
		MinHeight:        600,
		BackgroundColour: &options.RGBA{R: 17, G: 17, B: 17, A: 255},
		AssetServer:      &assetserver.Options{Assets: assets},
		// Без блока Mac Wails выключает кнопку «развернуть» (zoomable = 0, darwin/window.go).
		Mac: &mac.Options{},
		OnStartup: func(c context.Context) {
			ctx = c
		},
		OnShutdown: func(context.Context) {
			slog.Info("stop")
		},
		// Второй запуск не открывает вторую копию — показывает окно первой.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: constant.AppID,
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				if ctx == nil {
					return
				}
				runtime.WindowUnminimise(ctx)
				runtime.WindowShow(ctx)
			},
		},
		Bind: []any{handler},
	})
	if err != nil {
		slog.Error("wails.Run", "error", err)
		return 1
	}
	return 0
}
