// Package assets embeds the admin UI files served by the HTTP server.
package assets

import (
	"embed"
	"io/fs"
)

//go:embed static
var embedded embed.FS

// Static returns the admin UI files rooted at the static directory, for
// example "app.js". The apple-touch-icon.png is served by its own route.
func Static() fs.FS {
	files, err := fs.Sub(embedded, "static")
	if err != nil {
		// The directory name is fixed at compile time by the embed directive.
		panic(err)
	}
	return files
}
