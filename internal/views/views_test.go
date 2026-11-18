package views

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type normalizeRule struct {
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

// normalize applies testdata/normalize.json, which the Rust goldens went
// through at capture time, to the Go output.
func normalize(t *testing.T, html string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "normalize.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Rules []normalizeRule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	for _, rule := range config.Rules {
		html = regexp.MustCompile(rule.Pattern).ReplaceAllString(html, rule.Replace)
	}
	return html
}

// assertGolden compares the normalised page with testdata/<name>.golden.html
// byte for byte.
func assertGolden(t *testing.T, name, html string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name+".golden.html"))
	if err != nil {
		t.Fatal(err)
	}
	got := normalize(t, html)
	if got != string(want) {
		t.Errorf("%s differs from the Rust golden:\n got: %.400q\nwant: %.400q", name, firstDifference(got, string(want)), firstDifference(string(want), got))
	}
}

// firstDifference returns the text of a from a little before where it first
// departs from b.
func firstDifference(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return a[max(i-60, 0):]
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
