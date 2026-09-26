package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:build
var built embed.FS

func Handler() http.Handler {
	files, err := fs.Sub(built, "build")
	if err != nil {
		panic(err)
	}
	server := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" && (strings.HasSuffix(r.URL.Path, "/") || strings.HasSuffix(r.URL.Path, "/index.html")) {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(r.URL.Path, "/_app/immutable/") {
			if info, err := fs.Stat(files, strings.TrimPrefix(r.URL.Path, "/")); err == nil && !info.IsDir() {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
		}
		server.ServeHTTP(w, r)
	})
}
