// Package constant — общие константы программы.
package constant

const (
	// AppName — имя программы и папки данных.
	AppName = "Brassbox"

	// AppID — постоянный id для SingleInstanceLock (второй запуск находит первый по нему). Не менять.
	AppID = "kz.brassbox.app"

	// DataDirEnv — переопределить папку данных (тесты, разработка).
	DataDirEnv = "BRASSBOX_DATA_DIR"

	// DebugEnv — подробные логи (+ вывод в консоль).
	DebugEnv = "BRASSBOX_DEBUG"
)

// Version подставляется при сборке: -ldflags "-X brassbox/internal/constant.Version=1.2.3".
var Version = "0.0.0-dev"
