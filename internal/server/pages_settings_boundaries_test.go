package server

import (
	"testing"

	"github.com/henry40408/noadd/internal/views"
)

func TestSettingsPageFallsBackToTheDnsLayerDefaultsForUnsetValues(t *testing.T) {
	page := settingsPageFor(views.ShellData{}, map[string]string{}, nil, false)
	if page.UpstreamStrategy != "sequential" || page.BlockMode != "null_ip" || page.DoHAccessPolicy != "allow" {
		t.Errorf("defaults = %q %q %q", page.UpstreamStrategy, page.BlockMode, page.DoHAccessPolicy)
	}
	if !page.DNSSECOn {
		t.Error("DNSSEC is on unless it was disabled")
	}
	if page.Saved || page.ErrorField != "" || page.ErrorMessage != "" {
		t.Errorf("a plain page carries no notice: %+v", page)
	}
}

func TestSettingsPageShowsTheValuesItIsGiven(t *testing.T) {
	page := settingsPageFor(views.ShellData{}, map[string]string{
		"upstream_strategy": "round_robin", "block_mode": "custom_ip", "doh_access_policy": "deny",
		"dnssec_disabled": "true", "upstream_servers": "9.9.9.9:53", "log_retention_days": "45",
		"public_url": "https://dns.example", "block_custom_ipv4": "192.0.2.1", "block_custom_ipv6": "100::",
	}, &settingsFailure{field: "public_url", message: "bad"}, true)
	if page.UpstreamStrategy != "round_robin" || page.BlockMode != "custom_ip" || page.DoHAccessPolicy != "deny" {
		t.Errorf("stored values lost: %q %q %q", page.UpstreamStrategy, page.BlockMode, page.DoHAccessPolicy)
	}
	if page.DNSSECOn {
		t.Error("DNSSEC shows on although it was disabled")
	}
	if page.UpstreamServers != "9.9.9.9:53" || page.LogRetentionDays != "45" || page.PublicURL != "https://dns.example" ||
		page.BlockCustomIPv4 != "192.0.2.1" || page.BlockCustomIPv6 != "100::" {
		t.Errorf("stored values lost: %+v", page)
	}
	if !page.Saved || page.ErrorField != "public_url" || page.ErrorMessage != "bad" {
		t.Errorf("notice lost: %+v", page)
	}
}

func TestSettingsPageTreatsOnlyAnExactTrueAsDnssecDisabled(t *testing.T) {
	cases := map[string]bool{"": true, "false": true, "TRUE": true, "true": false, " true ": false}
	for stored, wantOn := range cases {
		page := settingsPageFor(views.ShellData{}, map[string]string{"dnssec_disabled": stored}, nil, false)
		if page.DNSSECOn != wantOn {
			t.Errorf("dnssec_disabled=%q: DNSSECOn = %v, want %v", stored, page.DNSSECOn, wantOn)
		}
	}
}

func TestSettingsPageReadsEveryStoredSettingFromTheDatabase(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	stored := map[string]string{
		"upstream_servers": "9.9.9.9:53", "log_retention_days": "45", "public_url": "https://dns.example",
		"block_custom_ipv4": "192.0.2.1",
	}
	for key, value := range stored {
		if err := h.db.SetSetting(ctxBackground(), key, value); err != nil {
			t.Fatal(err)
		}
	}
	body := h.pageBody("/settings")
	for _, value := range stored {
		wantContains(t, body, value)
	}
}
