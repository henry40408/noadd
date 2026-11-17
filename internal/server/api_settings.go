package server

import (
	"context"
	"net/http"
	"sort"
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
	var servers []string
	if !settingsValid(settings, &servers) {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	ctx := writeCtx(r)
	if err := a.persistSettings(ctx, settings); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	a.applyRuntimeSettings(ctx, settings, servers)
	writeStatus(w, http.StatusOK)
}

// settingsValid reports whether every value passes, before anything is
// written, so a bad value rejects the whole request. It fills servers with the
// parsed upstream list when one was given.
func settingsValid(settings map[string]string, servers *[]string) bool {
	if value, present := settings["upstream_servers"]; present {
		parsed, err := upstream.ParseUpstreams(value)
		if err != nil {
			return false
		}
		*servers = parsed
	}
	if mode, present := settings["block_mode"]; present && !dns.ValidBlockMode(mode) {
		return false
	}
	if value := strings.TrimSpace(settings["block_custom_ipv4"]); value != "" && !dns.ValidCustomIPv4(value) {
		return false
	}
	if value := strings.TrimSpace(settings["block_custom_ipv6"]); value != "" && !dns.ValidCustomIPv6(value) {
		return false
	}
	return true
}

// persistSettings stores every key. Values are stored as sent, untrimmed, as in
// Rust; readers trim.
func (a *api) persistSettings(ctx context.Context, settings map[string]string) error {
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
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
