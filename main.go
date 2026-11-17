// Brassbox — хранилище паролей и документации (Wails + Vue).
// main тонкий: встраивает собранный фронт и передаёт управление internal/app.
package main

import (
	"embed"
	"io/fs"
	"os"

	"brassbox/internal/app"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	dist, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		panic(err)
	}
	os.Exit(app.Run(dist))
}
