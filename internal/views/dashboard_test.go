package views

import (
	"strings"
	"testing"
)

func emptyDashboard() DashboardPage {
	return DashboardPage{
		Shell:        ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/"},
		QueriesToday: "0", QueriesTodayFull: "0", Queries7d: "0", Queries30d: "0",
		BlockedToday: "0", BlockedTodayFull: "0", Blocked7d: "0", Blocked30d: "0",
		BlockRate: "0.0", BlockRate7d: "0.0", BlockRate30d: "0.0",
		CacheRate: "0.0", CacheRate7d: "0.0", CacheRate30d: "0.0",
		AvgMS: "0", AvgMS7d: "0", AvgMS30d: "0",
		QPSNow: "0.00", QPSToday: "0.00", QPS7d: "0.00",
		DNSAddr: "127.0.0.1:53",
	}
}

func dataDashboard() DashboardPage {
	page := emptyDashboard()
	page.HasQueries = true
	page.QueriesToday, page.QueriesTodayFull, page.Queries7d, page.Queries30d = "200", "200", "200", "200"
	page.BlockedToday, page.BlockedTodayFull, page.Blocked7d, page.Blocked30d = "80", "80", "80", "80"
	page.BlockRate, page.BlockRate7d, page.BlockRate30d = "40.0", "40.0", "40.0"
	page.CacheRate, page.CacheRate7d, page.CacheRate30d = "92.5", "92.5", "92.5"
	page.AvgMS, page.AvgMS7d, page.AvgMS30d = "1", "1", "1"
	page.QPSNow = "3.33"
	page.TopDomains = []TopRow{
		{Label: "allowed.example.com", Count: "42", Share: "24.1%"},
		{Label: "ads.example.com", Count: "28", Share: "16.1%"},
		{Label: "ads.list-one.test", Count: "13", Share: "7.5%"},
		{Label: "adserver.list-two.test", Count: "13", Share: "7.5%"},
		{Label: "cname.example.com", Count: "13", Share: "7.5%"},
		{Label: "dnssec.example.com", Count: "13", Share: "7.5%"},
		{Label: "nodata.example.com", Count: "13", Share: "7.5%"},
		{Label: "nxd.example.com", Count: "13", Share: "7.5%"},
		{Label: "ok.ads.example.com", Count: "13", Share: "7.5%"},
		{Label: "ok.list-two.test", Count: "13", Share: "7.5%"},
	}
	page.TopClients = []TopRow{
		{Label: "192.168.215.1", Count: "100", Share: "50.0%"},
		{Label: "192.168.215.1", SubLabel: "alpha-token", Count: "50", Share: "25.0%"},
		{Label: "192.168.215.1", SubLabel: "beta-token", Count: "50", Share: "25.0%"},
	}
	page.TopUpstreams = []TopRow{{Label: "0.250.250.254:15353", Count: "9", Share: "100.0%", AvgMS: "5ms"}}
	return page
}

func TestDashboardMatchesGoldens(t *testing.T) {
	assertGolden(t, "dashboard_empty", Dashboard(emptyDashboard()))
	assertGolden(t, "dashboard_data", Dashboard(dataDashboard()))
	welcome := emptyDashboard()
	welcome.Shell.Welcome = true
	assertGolden(t, "dashboard_welcome", Dashboard(welcome))
}

// The flash banners live in the shell, so the dashboard carries every one.
func TestDashboardFlashShellMatchesGoldens(t *testing.T) {
	cases := map[string]func(*ShellData){
		"flash_welcome":          func(s *ShellData) { s.Welcome = true },
		"flash_proxy_logout":     func(s *ShellData) { s.ProxyLogoutNotice = true },
		"flash_password_changed": func(s *ShellData) { s.PasswordChanged = true },
		"flash_lists_updating":   func(s *ShellData) { s.ListsUpdating = true },
		"flash_sessions_revoked": func(s *ShellData) { s.SessionsRevoked = true },
		"flash_filters_saved":    func(s *ShellData) { s.FiltersSaved = true },
		"flash_account_saved":    func(s *ShellData) { s.AccountSaved = true },
		"flash_logs_cleared":     func(s *ShellData) { s.LogsCleared = true },
		"flash_settings_saved":   func(s *ShellData) { s.SettingsSaved = true },
	}
	for name, set := range cases {
		page := dataDashboard()
		set(&page.Shell)
		assertGolden(t, name, Dashboard(page))
	}
}

// 待 Opus 審查: XSS. Every string a page shows, however it got into the
// database or the Host header, must come out escaped.
func TestDashboardEscapesEveryString(t *testing.T) {
	const payload = `<script>alert("x")</script>`
	page := dataDashboard()
	page.Shell.Host = payload
	page.TopDomains = []TopRow{{Label: payload, Count: payload, Share: payload}}
	page.TopClients = []TopRow{{Label: payload, SubLabel: payload, Count: "1"}}
	page.TopUpstreams = []TopRow{{Label: payload, Count: "1", AvgMS: payload}}
	out := Dashboard(page)
	if strings.Contains(out, "<script>alert") {
		t.Fatal("unescaped payload in dashboard output")
	}
	if !strings.Contains(out, `title="&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"`) {
		t.Error("attribute value was not escaped")
	}
}
