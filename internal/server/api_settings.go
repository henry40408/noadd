package server

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/henry40408/noadd/internal/dns"
	"github.com/henry40408/noadd/internal/upstream"
)

// settingKeys are the keys GET /api/settings reports.
var settingKeys = []string{
	"upstream_servers", "upstream_strategy", "log_retention_days", "doh_access_policy",
	"public_url", "onboarding_banner_dismissed", "dnssec_disabled", "block_mode",
	"block_custom_ipv4", "block_custom_ipv6",
}

// getSettings handles GET /api/settings: only known keys that are stored.
func (a *api) getSettings(w http.ResponseWriter, r *http.Request, _ authedUser) {
	settings := map[string]string{}
	for _, key := range settingKeys {
		value, found, err := a.DB.GetSetting(r.Context(), key)
		if err == nil && found {
			settings[key] = value
		}
	}
	writeJSON(w, http.StatusOK, settings)
}

// decodeSettings reads a flat string map. A null or non-string value is a 422
// as with serde, where Go would silently take null as "".
func decodeSettings(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	var raw map[string]*string
	if !decodeJSON(w, r, &raw) {
		return nil, false
	}
	settings := make(map[string]string, len(raw))
	for key, value := range raw {
		if value == nil {
			writeText(w, http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type")
			return nil, false
		}
		settings[key] = *value
	}
	return settings, true
}

// putSettings handles PUT /api/settings. A bad value answers a bare 400.
func (a *api) putSettings(w http.ResponseWriter, r *http.Request, _ authedUser) {
	settings, ok := decodeSettings(w, r)
	if !ok {
		return
	}
	failure := a.applySettings(writeCtx(r), settings)
	switch {
	case failure == nil:
		writeStatus(w, http.StatusOK)
	case failure.internal:
		writeStatus(w, http.StatusInternalServerError)
	default:
		writeStatus(w, http.StatusBadRequest)
	}
}

// settingsFailure is why a settings save was refused. The API answers a bare
// status; the settings page uses field to place the message beside the input.
type settingsFailure struct {
	field    string
	message  string
	internal bool
}

// applySettings validates, persists and applies runtime settings. Shared by
// PUT /api/settings and the settings form. Everything is validated before
// anything is written, so a bad value rejects the whole save.
func (a *api) applySettings(ctx context.Context, settings map[string]string) *settingsFailure {
	var servers []string
	if failure := validateSettings(settings, &servers); failure != nil {
		return failure
	}
	if err := a.persistSettings(ctx, settings); err != nil {
		return &settingsFailure{internal: true}
	}
	a.applyRuntimeSettings(ctx, settings, servers)
	return nil
}

// validateSettings checks every value before anything is written. It fills
// servers with the parsed upstream list when one was given.
func validateSettings(settings map[string]string, servers *[]string) *settingsFailure {
	if value, present := settings["upstream_servers"]; present {
		parsed, err := upstream.ParseUpstreams(value)
		if err != nil {
			return &settingsFailure{
				field:   "upstream_servers",
				message: "Not a valid upstream — use ip:port, tls://host, or https://host/dns-query",
			}
		}
		*servers = parsed
	}
	if mode, present := settings["block_mode"]; present && !dns.ValidBlockMode(mode) {
		return &settingsFailure{field: "block_mode", message: "Unknown block mode"}
	}
	if value := strings.TrimSpace(settings["block_custom_ipv4"]); value != "" && !dns.ValidCustomIPv4(value) {
		return &settingsFailure{field: "block_custom_ipv4", message: "Not a valid IPv4 address"}
	}
	if value := strings.TrimSpace(settings["block_custom_ipv6"]); value != "" && !dns.ValidCustomIPv6(value) {
		return &settingsFailure{field: "block_custom_ipv6", message: "Not a valid IPv6 address"}
	}
	return nil
}

// persistSettings stores every key. Values are stored as sent, untrimmed, as in
// Rust; readers trim.
func (a *api) persistSettings(ctx context.Context, settings map[string]string) error {
	for _, key := range slices.Sorted(maps.Keys(settings)) {
		if err := a.DB.SetSetting(ctx, key, settings[key]); err != nil {
			return err
		}
	}
	return nil
}

// applyRuntimeSettings makes stored changes take effect without a restart. It
// runs only after the values are persisted.
func (a *api) applyRuntimeSettings(ctx context.Context, settings map[string]string, servers []string) {
	if value, present := settings["upstream_strategy"]; present {
		if strategy, err := upstream.ParseStrategy(value); err == nil {
			a.Forwarder.SetStrategy(strategy)
		}
	}
	if value, present := settings["dnssec_disabled"]; present {
		enabled := strings.TrimSpace(value) != "true"
		// Flush only on a real flip: cached wire responses carry the old
		// AD/RRSIG/OPT state, but re-saving the same value must not wipe the cache.
		if a.Forwarder.DNSSECEnabled() != enabled {
			a.Forwarder.SetDNSSECEnabled(enabled)
			a.Cache.InvalidateAll()
		}
	}
	if servers != nil {
		a.Forwarder.Reconfigure(ctx, servers)
	}
	if hasBlockSetting(settings) {
		a.Handler.SetBlockConfig(dns.BlockConfigFromSettings(
			a.mergedSetting(ctx, settings, "block_mode"),
			a.mergedSetting(ctx, settings, "block_custom_ipv4"),
			a.mergedSetting(ctx, settings, "block_custom_ipv6"),
		))
	}
}

func hasBlockSetting(settings map[string]string) bool {
	for key := range settings {
		if strings.HasPrefix(key, "block_") {
			return true
		}
	}
	return false
}

// mergedSetting prefers the value just submitted over the stored one.
func (a *api) mergedSetting(ctx context.Context, submitted map[string]string, key string) string {
	if value, present := submitted[key]; present {
		return value
	}
	value, _, _ := a.DB.GetSetting(ctx, key)
	return value
}
