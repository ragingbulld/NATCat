package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

func StaticFS() (fs.FS, error) {
	return fs.Sub(dist, "dist")
}
