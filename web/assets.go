package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html app.js grants.js charts.js style.css
var assets embed.FS

func Files() fs.FS { return assets }
