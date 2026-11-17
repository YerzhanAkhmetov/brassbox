# Brassbox — команды разработки. `make help` — список.
VERSION ?= 0.0.0-dev
LDFLAGS := -X brassbox/internal/constant.Version=$(VERSION)
GOBIN   := $(shell go env GOPATH)/bin

.PHONY: help dev build build-win test test-go test-front lint generate dist

help: ## список команд
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

dist: # go:embed не принимает пустую папку frontend/dist
	@mkdir -p frontend/dist && touch frontend/dist/.gitkeep

dev: ## окно с горячей перезагрузкой; данные — tests/data, не настоящие
	BRASSBOX_DEBUG=1 BRASSBOX_DATA_DIR="$(CURDIR)/tests/data" wails dev -ldflags "$(LDFLAGS)"

build: ## Mac: build/bin/Brassbox.app
	wails build -clean -ldflags "$(LDFLAGS)"

build-win: ## Windows: build/bin/Brassbox.exe (собирается на Mac)
	wails build -platform windows/amd64 -ldflags "$(LDFLAGS)"

generate: dist ## JS-обёртки Go-методов → frontend/wailsjs
	wails generate module

test: test-go test-front ## все тесты

test-go: dist ## Go-тесты
	go test -count=1 ./...

test-front: ## Vitest
	cd frontend && pnpm test

lint: dist ## golangci-lint + eslint + проверка типов
	$(GOBIN)/golangci-lint run ./...
	cd frontend && pnpm lint && pnpm exec vue-tsc -b
