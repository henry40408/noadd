package views

import (
	"strings"
	"testing"
)

func settingsPage() SettingsPage {
	return SettingsPage{
		Shell:                      ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/settings"},
		UpstreamStrategy:           "sequential",
		DNSSECOn:                   true,
		BlockMode:                  "null_ip",
		DoHAccessPolicy:            "allow",
		BlockCustomIPv4Suggestions: []string{"0.0.0.0", "127.0.0.1", "192.0.2.1"},
		BlockCustomIPv6Suggestions: []string{"::", "::1", "100::"},
		LogRetentionSuggestions:    []string{"1", "7", "14", "30", "90", "365"},
	}
}

func TestSettingsMatchesGoldens(t *testing.T) {
	empty := settingsPage()
	empty.Shell.ShowNextStep, empty.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "settings_empty", Settings(empty))

	data := settingsPage()
	data.UpstreamServers = "0.250.250.254:15353"
	data.LogRetentionDays = "30"
	data.PublicURL = "https://dns.example.test"
	assertGolden(t, "settings_data", Settings(data))

	failed := data
	failed.UpstreamServers = "bad upstream"
	failed.ErrorField = "upstream_servers"
	failed.ErrorMessage = "Not a valid upstream — use ip:port, tls://host, or https://host/dns-query"
	assertGolden(t, "settings_error", Settings(failed))
}

// 待 Opus 審查: XSS. Every submitted value is echoed back on a rejected save.
func TestSettingsEscapesEveryString(t *testing.T) {
	const payload = `"><script>alert(1)</script>`
	page := settingsPage()
	page.UpstreamServers, page.BlockCustomIPv4, page.BlockCustomIPv6 = payload, payload, payload
	page.LogRetentionDays, page.PublicURL = payload, payload
	page.BlockCustomIPv4Suggestions = []string{payload}
	page.ErrorField, page.ErrorMessage = "public_url", payload
	if strings.Contains(Settings(page), "<script>alert") {
		t.Fatal("unescaped payload in settings output")
	}
}

func TestSettingsSavedMarker(t *testing.T) {
	page := settingsPage()
	page.Saved = true
	if !strings.Contains(Settings(page), `data-testid="settings-saved"`) {
		t.Fatal("saved marker missing")
	}
}
