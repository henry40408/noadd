package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"
)

func TestSipHashMatchesTheReferenceAtEveryWordBoundary(t *testing.T) {
	// Vectors come from an independent SipHash-1-3 (zero key) implementation.
	cases := map[string]uint64{
		"":                 0xd1fba762150c532c,
		"abcdefgh":         0x3f7b849c0b8e35ea,
		"abcdefghi":        0xf89b34a3d11eb6e5,
		"abcdefghijklmnop": 0x94f60d3d29e6a312,
	}
	for input, want := range cases {
		if got := sipHash13([]byte(input)); got != want {
			t.Errorf("sipHash13(%q) = %016x, want %016x", input, got, want)
		}
	}
}

func TestContentTypeFollowsTheExtensionCaseInsensitively(t *testing.T) {
	cases := map[string]string{
		"app.css": "text/css", "APP.JS": "text/javascript", "i.svg": "image/svg+xml", "a/b.png": "image/png",
		"data.json": "application/json", "noextension": "application/octet-stream", "x.unknownext": "application/octet-stream",
	}
	for name, want := range cases {
		got := contentTypeFor(name)
		if name == "data.json" {
			if got == "application/octet-stream" || got == "" {
				t.Errorf("contentTypeFor(%q) = %q, want a guessed type", name, got)
			}
			continue
		}
		if got != want {
			t.Errorf("contentTypeFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestStaticFilesIncludeNestedFilesAndSkipDirectories(t *testing.T) {
	served, err := newStaticFiles(fstest.MapFS{
		"top.css":      {Data: []byte("a{}")},
		"dir/deep.js":  {Data: []byte("1")},
		"dir/more.svg": {Data: []byte("<svg/>")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(served.files) != 3 {
		t.Fatalf("files = %d, want 3", len(served.files))
	}
	for _, name := range []string{"top.css", "dir/deep.js", "dir/more.svg"} {
		if served.files[name].etag == "" {
			t.Errorf("%s missing", name)
		}
	}
	if _, isDir := served.files["dir"]; isDir {
		t.Error("a directory was served as a file")
	}
}

func TestHookRunsFromTheFirstFinalStatusNotFromInterimOnes(t *testing.T) {
	cases := map[int]bool{
		http.StatusContinue: false, http.StatusProcessing: false, 199: false,
		http.StatusSwitchingProtocols: true, http.StatusOK: true, http.StatusNotFound: true,
	}
	for status, wantRun := range cases {
		ran := 0
		writer := &hookedWriter{ResponseWriter: httptest.NewRecorder(), hook: func(http.Header) { ran++ }}
		writer.WriteHeader(status)
		if (ran == 1) != wantRun {
			t.Errorf("status %d: hook ran %d times, want run=%v", status, ran, wantRun)
		}
	}
}

func TestServerTimeoutsAreTheDocumentedOnes(t *testing.T) {
	server := NewHTTPServer(":0", http.NotFoundHandler())
	if server.ReadHeaderTimeout != 10*time.Second || server.IdleTimeout != 120*time.Second {
		t.Errorf("timeouts = %v / %v", server.ReadHeaderTimeout, server.IdleTimeout)
	}
}

func TestTheDnsTargetKeepsTheHostWhenThePortIsMissingOrBare(t *testing.T) {
	cases := []struct{ browserHost, dnsAddr, want string }{
		{"noadd.lan:8080", "0.0.0.0:", "noadd.lan"},
		{"noadd.lan", "0.0.0.0:53", "noadd.lan:53"},
		{"noadd.lan:8080", ":53", "noadd.lan:53"},
	}
	for _, c := range cases {
		if got := dnsTarget(c.browserHost, c.dnsAddr); got != c.want {
			t.Errorf("dnsTarget(%q, %q) = %q, want %q", c.browserHost, c.dnsAddr, got, c.want)
		}
	}
}
