// Package wails — методы Go, которые вызывает фронт (window.go.wails.Handler.*).
// ⚠️ Wails отдаёт фронту ВСЕ экспортируемые методы Handler — служебные методы сюда не класть.
package wails

import (
	"brassbox/internal/constant"
)

// Handler — методы для фронта.
type Handler struct{}

// New создаёт Handler.
func New() *Handler {
	return &Handler{}
}

// Version — версия программы; заодно проверка связи фронт ↔ Go.
func (h *Handler) Version() string {
	return constant.Version
}
