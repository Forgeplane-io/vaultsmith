package web

import (
	"bytes"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist/*
var embeddedFiles embed.FS

func Files() fs.FS {
	files, err := fs.Sub(embeddedFiles, "dist")
	if err != nil {
		panic("embedded frontend assets are unavailable")
	}
	return files
}

func New(staticFiles fs.FS, api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.Handle("/healthz", api)
	mux.Handle("/readyz", api)
	mux.Handle("/", staticHandler{files: staticFiles})
	return mux
}

type staticHandler struct {
	files fs.FS
}

func (s staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setStaticHeaders(w)
	requested := strings.TrimPrefix(r.URL.Path, "/")
	if requested == "" {
		requested = "index.html"
	}
	if !fs.ValidPath(requested) {
		http.NotFound(w, r)
		return
	}

	if info, err := fs.Stat(s.files, requested); err == nil && !info.IsDir() {
		s.serveFile(w, r, requested)
		return
	}
	if strings.HasPrefix(requested, "assets/") || path.Ext(requested) != "" {
		http.NotFound(w, r)
		return
	}
	if _, err := fs.Stat(s.files, "index.html"); err != nil {
		http.NotFound(w, r)
		return
	}
	s.serveFile(w, r, "index.html")
}

func (s staticHandler) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	file, err := s.files.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, path.Base(name), info.ModTime(), bytes.NewReader(contents))
}

func setStaticHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'")
}
