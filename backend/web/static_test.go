package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testAssets() fs.FS {
	return fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<html>vault desk</html>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	}
}

func TestStaticFilesAndSPAFallback(t *testing.T) {
	handler := New(testAssets(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "root", path: "/", want: "vault desk"},
		{name: "browser route", path: "/profiles/dev", want: "vault desk"},
		{name: "asset", path: "/assets/app.js", want: "console.log"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("body = %q, want substring %q", response.Body.String(), test.want)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestMissingStaticAssetsAreNotSPAFallbacks(t *testing.T) {
	handler := New(testAssets(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	for _, path := range []string{"/assets/missing.js", "/favicon.ico"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/../index.html", nil)
	response := httptest.NewRecorder()
	staticHandler{files: testAssets()}.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("traversal status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAPIRoutesDelegate(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("api"))
	})
	handler := New(testAssets(), api)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/profiles", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTeapot || response.Body.String() != "api" {
		t.Fatalf("response = %d %q, want 418 api", response.Code, response.Body.String())
	}
}
