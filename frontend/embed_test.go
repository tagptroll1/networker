package frontend

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedUI(t *testing.T) {
	server := Handler()
	assets, err := fs.Glob(built, "build/_app/immutable/entry/*.js")
	if err != nil || len(assets) == 0 {
		t.Fatal("no built JavaScript assets")
	}
	immutable := "/" + strings.TrimPrefix(assets[0], "build/")
	for _, path := range []string{"/", "/world.svg", immutable} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 200 {
			t.Fatalf("%s: %d", path, response.Code)
		}
		if path == "/" && !strings.Contains(response.Body.String(), "lang=\"en\"") {
			t.Fatal("missing English UI")
		}
		wantCache := ""
		switch path {
		case "/":
			wantCache = "no-cache"
		case immutable:
			wantCache = "public, max-age=31536000, immutable"
		}
		if got := response.Header().Get("Cache-Control"); got != wantCache {
			t.Errorf("%s: cache = %q, want %q", path, got, wantCache)
		}
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodHead, immutable, nil))
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("HEAD asset: code %d, body %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: code %d, Allow %q", response.Code, response.Header().Get("Allow"))
	}
	for _, path := range []string{"/missing", "/missing/", "/index.html"} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if response.Code != 404 {
			t.Fatalf("%s: want 404, got %d", path, response.Code)
		}
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/_app/immutable/missing.js", nil))
	if response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "" {
		t.Fatalf("missing immutable asset: code %d, cache %q", response.Code, response.Header().Get("Cache-Control"))
	}
}
