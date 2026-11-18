package server

import (
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// staticFile is one embedded file with its precomputed validators.
type staticFile struct {
	body        []byte
	etag        string
	contentType string
}

// staticFiles serves embedded files with an ETag and Cache-Control: no-cache,
// so browsers revalidate and get 304 while a file is unchanged.
type staticFiles struct {
	files map[string]staticFile
}

// appleTouchIconFile is served by its own route, which answers 405 to methods
// other than GET and HEAD.
const appleTouchIconFile = "apple-touch-icon.png"

// contentTypes pins the types the admin UI uses: the platform tables differ
// (charset suffixes, text/javascript), and the Rust build answered these.
var contentTypes = map[string]string{
	".css": "text/css",
	".js":  "text/javascript",
	".svg": "image/svg+xml",
	".png": "image/png",
}

func contentTypeFor(name string) string {
	extension := strings.ToLower(path.Ext(name))
	if known, ok := contentTypes[extension]; ok {
		return known
	}
	if guessed := mime.TypeByExtension(extension); guessed != "" {
		return guessed
	}
	return "application/octet-stream"
}

// newStaticFiles reads every file under root once.
func newStaticFiles(root fs.FS) (*staticFiles, error) {
	served := &staticFiles{files: make(map[string]staticFile)}
	err := fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		body, err := fs.ReadFile(root, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		served.files[name] = staticFile{body: body, etag: contentETag(body), contentType: contentTypeFor(name)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return served, nil
}

// ServeHTTP serves the file named by the request path, or 404. There is no
// SPA fallback: every page path is a real route, so an unmatched path has no
// page. Any method is served, as the Rust fallback did.
func (s *staticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	file, ok := s.files[strings.TrimLeft(r.URL.Path, "/")]
	if !ok {
		writeText(w, http.StatusNotFound, "not found")
		return
	}
	serveRevalidated(w, r, file)
}

// serveRevalidated answers 304 when If-None-Match lists the file's ETag,
// otherwise 200 with the body.
func serveRevalidated(w http.ResponseWriter, r *http.Request, file staticFile) {
	header := w.Header()
	header.Set("ETag", file.etag)
	header.Set("Cache-Control", "no-cache")
	if ifNoneMatchLists(r, file.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", file.contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(file.body)
}

// ifNoneMatchLists reports whether If-None-Match names etag. A comma-separated
// list is tolerated; a weak validator or "*" does not match, as before.
func ifNoneMatchLists(r *http.Request, etag string) bool {
	for _, value := range r.Header.Values("If-None-Match") {
		for _, candidate := range strings.Split(value, ",") {
			if strings.TrimSpace(candidate) == etag {
				return true
			}
		}
	}
	return false
}

// appleTouchIconHandler serves the iOS home-screen icon.
func appleTouchIconHandler(icon staticFile) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET,HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		serveRevalidated(w, r, icon)
	})
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
