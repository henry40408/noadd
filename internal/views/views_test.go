package views

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// normalizeRules are applied in order, RE2 syntax, to the Rust golden HTML at
// capture time and to the Go output before it is digested. The Go side renders
// its own version string as v0.41.1 and applies the last rule too.
var normalizeRules = []struct {
	pattern *regexp.Regexp
	replace string
}{
	{regexp.MustCompile(`data-ts="\d+"`), `data-ts="<TS>"`},
	{regexp.MustCompile(`data-date-ts="\d+"`), `data-date-ts="<TS>"`},
	{regexp.MustCompile(`(?:just now|\d+ (?:seconds?|minutes?|hours?|days?|months?|years?) ago)`), "<AGO>"},
	{regexp.MustCompile(`noadd_[A-Za-z0-9_-]{4,}`), "<APIKEY>"},
	{regexp.MustCompile(`[\d.]+((?:<span[^>]*>)?\s?ms\b)`), "<MS>${1}"},
	{regexp.MustCompile(`v0\.41\.1`), "<VERSION>"},
}

func normalize(html string) string {
	for _, rule := range normalizeRules {
		html = rule.pattern.ReplaceAllString(html, rule.replace)
	}
	return html
}

// assertGolden compares the sha256 of the normalised page with the digest of
// the Rust golden of the same name (goldenDigests), so it is a byte for byte
// comparison. On a mismatch the page is written to a temp file, to diff
// against the golden kept in git history.
func assertGolden(t *testing.T, name, html string) {
	t.Helper()
	want, ok := goldenDigests[name]
	if !ok {
		t.Fatalf("no golden digest named %s", name)
	}
	got := normalize(html)
	sum := sha256.Sum256([]byte(got))
	if hex.EncodeToString(sum[:]) == want {
		return
	}
	file, err := os.CreateTemp("", name+".actual.*.html")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(got); err != nil {
		t.Fatal(err)
	}
	path := "internal/views/testdata/" + name + ".golden.html"
	t.Errorf("%s differs from the Rust golden (%d bytes of normalised output written to %s).\n"+
		"The golden is in git history: git show $(git log --diff-filter=D --format=%%h -1 -- %s)^:%s",
		name, len(got), file.Name(), path, path)
}

const goldenVersion = "v0.41.1"

func TestLoginMatchesGoldens(t *testing.T) {
	assertGolden(t, "login_page", Login(LoginPage{Version: goldenVersion}))
}

func TestSetupMatchesGoldens(t *testing.T) {
	assertGolden(t, "setup_empty", Setup(SetupPage{MinPasswordLength: 12}))
}

func TestLoginErrorMatchesGolden(t *testing.T) {
	page := LoginPage{Version: goldenVersion, Error: "ERR: incorrect password — access denied", Username: "admin"}
	assertGolden(t, "login_error", Login(page))
}

func TestSetupErrorsMatchGoldens(t *testing.T) {
	cases := map[string]string{
		"setup_error_bad_token": "setup token is missing or wrong; it is printed to the server's stderr at startup",
		"setup_error_mismatch":  "Passwords do not match",
		"setup_error_weak":      "password must be at least 12 characters",
	}
	for name, message := range cases {
		assertGolden(t, name, Setup(SetupPage{Error: message, Username: "admin", MinPasswordLength: 12}))
	}
}

func TestLoginCarriesNextAndEscapesValues(t *testing.T) {
	page := Login(LoginPage{Next: "/logs?a=1&b=\"2\"", Username: `a"<b>`})
	for _, want := range []string{
		`<input type="hidden" name="next" value="/logs?a=1&amp;b=&quot;2&quot;">`,
		`value="a&quot;&lt;b&gt;"`,
	} {
		if !contains(page, want) {
			t.Errorf("page lacks %s", want)
		}
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
