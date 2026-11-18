package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/henry40408/noadd/internal/stats"
	"github.com/henry40408/noadd/internal/views"
)

// Addresses the settings form suggests for the custom block IPs: 0.0.0.0
// because the two fields are set independently, 192.0.2.1 is TEST-NET-1
// (RFC 5737) and 100:: the discard-only prefix (RFC 6666).
var (
	blockCustomIPv4Suggestions = []string{"0.0.0.0", "127.0.0.1", "192.0.2.1"}
	blockCustomIPv6Suggestions = []string{"::", "::1", "100::"}
)

// pageSettingKeys are the settings the page renders; an absent key reads empty.
var pageSettingKeys = []string{
	"upstream_servers", "upstream_strategy", "log_retention_days", "doh_access_policy",
	"public_url", "dnssec_disabled", "block_mode", "block_custom_ipv4", "block_custom_ipv6",
}

func (a *api) currentSettings(ctx context.Context) map[string]string {
	values := map[string]string{}
	for _, key := range pageSettingKeys {
		if value, found, err := a.DB.GetSetting(ctx, key); err == nil && found {
			values[key] = value
		}
	}
	return values
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func retentionSuggestions() []string {
	out := make([]string, 0, len(stats.LogRetentionDaysSuggestions))
	for _, days := range stats.LogRetentionDaysSuggestions {
		out = append(out, strconv.FormatInt(days, 10))
	}
	return out
}

// settingsPageFor builds the page from a set of values: the stored ones on a
// GET, the submitted ones on a rejected save, so only the wrong field needs
// correcting. Defaults mirror the DNS layer's fallbacks for an unset value.
func settingsPageFor(shell views.ShellData, values map[string]string, failure *settingsFailure, saved bool) views.SettingsPage {
	page := views.SettingsPage{
		Shell:                      shell,
		UpstreamServers:            values["upstream_servers"],
		UpstreamStrategy:           orDefault(values["upstream_strategy"], "sequential"),
		DNSSECOn:                   strings.TrimSpace(values["dnssec_disabled"]) != "true",
		BlockMode:                  orDefault(values["block_mode"], "null_ip"),
		BlockCustomIPv4:            values["block_custom_ipv4"],
		BlockCustomIPv6:            values["block_custom_ipv6"],
		LogRetentionDays:           values["log_retention_days"],
		PublicURL:                  values["public_url"],
		DoHAccessPolicy:            orDefault(values["doh_access_policy"], "allow"),
		BlockCustomIPv4Suggestions: blockCustomIPv4Suggestions,
		BlockCustomIPv6Suggestions: blockCustomIPv6Suggestions,
		LogRetentionSuggestions:    retentionSuggestions(),
		Saved:                      saved,
	}
	if failure != nil {
		page.ErrorField, page.ErrorMessage = failure.field, failure.message
	}
	return page
}

// settingsPage handles GET /settings.
func (a *api) settingsPage(w http.ResponseWriter, r *http.Request, _ authedUser) {
	shell := a.shell(w, r)
	writeHTML(w, http.StatusOK, views.Settings(settingsPageFor(shell, a.currentSettings(r.Context()), nil, shell.SettingsSaved)))
}

// settingsFormFields are every field the form submits; serde requires them all.
var settingsFormFields = []string{
	"upstream_servers", "upstream_strategy", "dnssec", "block_mode", "block_custom_ipv4",
	"block_custom_ipv6", "log_retention_days", "public_url", "doh_access_policy",
}

// settingsFromForm maps the form onto stored keys; dnssec on/off is the
// inverse of the stored dnssec_disabled.
func settingsFromForm(form map[string][]string) map[string]string {
	field := func(name string) string { return form[name][0] }
	dnssecDisabled := "false"
	if field("dnssec") == "off" {
		dnssecDisabled = "true"
	}
	return map[string]string{
		"upstream_servers":   field("upstream_servers"),
		"upstream_strategy":  field("upstream_strategy"),
		"dnssec_disabled":    dnssecDisabled,
		"block_mode":         field("block_mode"),
		"block_custom_ipv4":  field("block_custom_ipv4"),
		"block_custom_ipv6":  field("block_custom_ipv6"),
		"log_retention_days": field("log_retention_days"),
		"public_url":         field("public_url"),
		"doh_access_policy":  field("doh_access_policy"),
	}
}

// settingsSubmit handles POST /settings: one submit for every scalar setting,
// for use without JavaScript. Success redirects so a refresh cannot resubmit.
func (a *api) settingsSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, settingsFormFields...) {
		return
	}
	values := settingsFromForm(form)
	failure := a.applySettings(writeCtx(r), values)
	if failure == nil {
		setFlash(w, flashSettingsSaved)
		redirectSeeOther(w, r, "/settings")
		return
	}
	status := http.StatusBadRequest
	if failure.internal {
		status = http.StatusInternalServerError
		failure.message = "Could not save — check the server log"
	}
	// Re-render with what was submitted, not what is stored.
	writeHTML(w, status, views.Settings(settingsPageFor(a.shell(w, r), values, failure, false)))
}
