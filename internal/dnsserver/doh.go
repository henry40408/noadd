package dnsserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/dns"
	"github.com/henry40408/noadd/internal/netx"
)

const (
	dnsMessageContentType = "application/dns-message"

	// maxDoHBodyBytes is the request body limit; larger POST bodies get 413.
	// It is the limit the Rust server's body extractor applied.
	maxDoHBodyBytes = 2 * 1024 * 1024

	dohPolicySetting = "doh_access_policy"
	dohPolicyDeny    = "deny"
)

// DoHStore is the part of the database DoH needs; *db.DB implements it.
type DoHStore interface {
	GetSetting(ctx context.Context, key string) (value string, found bool, err error)
	// ValidateDohToken returns the token's name when the token exists.
	ValidateDohToken(ctx context.Context, token string) (name string, valid bool, err error)
}

// DoHConfig configures a DoH adapter.
type DoHConfig struct {
	Handler *Handler
	Store   DoHStore
	Trusted netx.TrustedProxies
	Slog    *slog.Logger
}

// DoH answers RFC 8484 queries on /dns-query and the token-authenticated
// /dns-query/{token}. The doh_access_policy setting "deny" rejects tokenless
// requests with 403; anything else, including unset, allows them.
type DoH struct {
	cfg DoHConfig
	log *slog.Logger
}

// NewDoH creates the DoH adapter.
func NewDoH(cfg DoHConfig) *DoH {
	log := cfg.Slog
	if log == nil {
		log = slog.Default()
	}
	return &DoH{cfg: cfg, log: log}
}

// Register mounts the DoH routes on mux. Both paths are registered without a
// method so that other methods get 405 here instead of falling through to a
// catch-all route.
func (d *DoH) Register(mux *http.ServeMux) {
	mux.HandleFunc("/dns-query", d.serve)
	mux.HandleFunc("/dns-query/{token}", d.serve)
}

func (d *DoH) serve(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		d.serveGet(w, r)
	case http.MethodPost:
		d.servePost(w, r)
	default:
		w.Header().Set("Allow", "GET,HEAD,POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// The order of checks below is the Rust server's: the request is parsed
// (query parameter, body) before any authorisation, so a malformed request
// gets 400 or 413 even when its token is wrong.

func (d *DoH) serveGet(w http.ResponseWriter, r *http.Request) {
	encoded, err := dnsQueryParameter(r.URL.RawQuery)
	if err != nil {
		writeText(w, http.StatusBadRequest, "Failed to deserialize query string: "+err.Error())
		return
	}
	tokenName, status := d.authorise(r)
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	query, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		writeText(w, http.StatusBadRequest, "invalid base64url encoding")
		return
	}
	d.answer(w, r, query, tokenName)
}

func (d *DoH) servePost(w http.ResponseWriter, r *http.Request) {
	body, err := readLimitedBody(w, r)
	if err != nil {
		writeBodyError(w, err)
		return
	}
	if !postContentTypeOK(r.Header) {
		writeText(w, http.StatusUnsupportedMediaType, "expected Content-Type: "+dnsMessageContentType)
		return
	}
	tokenName, status := d.authorise(r)
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	d.answer(w, r, body, tokenName)
}

// authorise applies the token or the open-access policy. A zero status means
// the request may proceed under tokenName (empty when tokenless).
func (d *DoH) authorise(r *http.Request) (tokenName string, status int) {
	token := r.PathValue("token")
	if token == "" {
		if !d.isOpenAccess(r.Context()) {
			return "", http.StatusForbidden
		}
		return "", 0
	}
	name, valid, err := d.cfg.Store.ValidateDohToken(r.Context(), token)
	if err != nil {
		d.log.Error("DoH token lookup failed", "event", "doh.token_lookup_failed", "error", err)
		return "", http.StatusInternalServerError
	}
	if !valid {
		return "", http.StatusForbidden
	}
	return name, 0
}

// isOpenAccess reports whether tokenless access is allowed: unless the policy
// is "deny". A failed lookup counts as open, as in the Rust server.
func (d *DoH) isOpenAccess(ctx context.Context) bool {
	policy, found, err := d.cfg.Store.GetSetting(ctx, dohPolicySetting)
	if err != nil {
		d.log.Warn("DoH access policy lookup failed; allowing tokenless access",
			"event", "doh.policy_lookup_failed", "error", err)
		return true
	}
	if !found {
		return true
	}
	return strings.TrimSpace(policy) != dohPolicyDeny
}

func (d *DoH) answer(w http.ResponseWriter, r *http.Request, query []byte, tokenName string) {
	if new(mdns.Msg).Unpack(query) != nil {
		writeText(w, http.StatusBadRequest, "malformed DNS message")
		return
	}
	response, err := d.cfg.Handler.Handle(r.Context(), Request{
		Bytes:    query,
		ClientIP: netx.RequestClientIP(r, d.cfg.Trusted),
		DoHToken: tokenName,
	})
	if err != nil {
		d.log.Warn("query handler failed; answering SERVFAIL",
			"event", "dns.handler_failed", "transport", "doh", "error", err)
		// RFC 8484 section 4.2.1: HTTP 200 with SERVFAIL, not 500, which makes
		// iOS disable the resolver.
		writeDNSMessage(w, dns.BuildServfail(query), 0)
		return
	}
	writeDNSMessage(w, response.Bytes, response.MinTTL)
}

func writeDNSMessage(w http.ResponseWriter, body []byte, maxAgeSeconds uint32) {
	header := w.Header()
	header.Set("Content-Type", dnsMessageContentType)
	header.Set("Cache-Control", fmt.Sprintf("max-age=%d", maxAgeSeconds))
	_, _ = w.Write(body)
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func readLimitedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxDoHBodyBytes))
}

func writeBodyError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeText(w, http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
		return
	}
	writeText(w, http.StatusBadRequest, "Failed to buffer the request body: "+err.Error())
}

// postContentTypeOK applies RFC 8484: a POST's Content-Type must be
// application/dns-message. Parameters are ignored, the match is case
// insensitive, and an absent header is accepted.
func postContentTypeOK(header http.Header) bool {
	values := header.Values("Content-Type")
	if len(values) == 0 {
		return true
	}
	for i := 0; i < len(values[0]); i++ {
		if c := values[0][i]; c > 0x7e || (c < 0x20 && c != '\t') {
			return false
		}
	}
	mediaType, _, _ := strings.Cut(values[0], ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), dnsMessageContentType)
}

// dnsQueryParameter extracts the dns parameter the way the Rust server's
// query deserializer did: form decoding that tolerates bad percent escapes,
// unknown keys ignored, and a repeated or missing dns an error. The error
// text completes "Failed to deserialize query string: ".
func dnsQueryParameter(rawQuery string) (string, error) {
	var value string
	found := false
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		key, rawValue, _ := strings.Cut(pair, "=")
		if formDecode(key) != "dns" {
			continue
		}
		if found {
			return "", errors.New("duplicate field `dns`")
		}
		value, found = formDecode(rawValue), true
	}
	if !found {
		return "", errors.New("missing field `dns`")
	}
	return value, nil
}

// formDecode decodes application/x-www-form-urlencoded text. A malformed
// percent escape stays as typed, and invalid UTF-8 becomes U+FFFD.
func formDecode(text string) string {
	if !strings.ContainsAny(text, "+%") {
		return text
	}
	decoded := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == '+':
			decoded = append(decoded, ' ')
		case c == '%' && i+2 < len(text) && isHex(text[i+1]) && isHex(text[i+2]):
			decoded = append(decoded, unhex(text[i+1])<<4|unhex(text[i+2]))
			i += 2
		default:
			decoded = append(decoded, c)
		}
	}
	return strings.ToValidUTF8(string(decoded), "�")
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
