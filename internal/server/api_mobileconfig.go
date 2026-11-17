package server

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const mobileConfigDescription = "Configures DNS-over-HTTPS to use noadd ad-blocking DNS server."

// getMobileConfig handles GET /api/mobileconfig/{token}. It needs no session:
// the DoH token in the path is the credential, and the profile only names the
// DoH endpoint that token already opens.
func (a *api) getMobileConfig(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	_, found, err := a.DB.ValidateDohToken(r.Context(), token)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	if !found {
		writeStatus(w, http.StatusNotFound)
		return
	}
	publicURL, found, err := a.DB.GetSetting(r.Context(), "public_url")
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	if !found || publicURL == "" {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="noadd-`+token+`.mobileconfig"`)
	_, _ = w.Write([]byte(mobileConfigPlist(token, strings.TrimRight(publicURL, "/"))))
}

// mobileConfigPlist renders the profile with the key order and tab indentation
// of the Rust plist writer; the UUIDs are deterministic (v5 over the URL
// namespace) so a reinstall replaces the profile instead of adding one.
func mobileConfigPlist(token, baseURL string) string {
	profileID := "com.noadd.dns." + token
	displayName := "noadd DNS (" + token + ")"
	payloadUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(token+"-payload")).String()
	profileUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(token+"-profile")).String()

	var b strings.Builder
	line := func(depth int, text string) {
		b.WriteString(strings.Repeat("\t", depth))
		b.WriteString(text)
		b.WriteByte('\n')
	}
	pair := func(depth int, key, value string) {
		line(depth, "<key>"+key+"</key>")
		line(depth, "<string>"+plistEscape(value)+"</string>")
	}
	integerPair := func(depth int, key string) {
		line(depth, "<key>"+key+"</key>")
		line(depth, "<integer>1</integer>")
	}

	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n")
	line(0, "<dict>")
	line(1, "<key>PayloadContent</key>")
	line(1, "<array>")
	line(2, "<dict>")
	line(3, "<key>DNSSettings</key>")
	line(3, "<dict>")
	pair(4, "DNSProtocol", "HTTPS")
	pair(4, "ServerURL", baseURL+"/dns-query/"+token)
	line(3, "</dict>")
	pair(3, "PayloadDisplayName", displayName)
	pair(3, "PayloadIdentifier", profileID+".dns")
	pair(3, "PayloadType", "com.apple.dnsSettings.managed")
	pair(3, "PayloadUUID", payloadUUID)
	integerPair(3, "PayloadVersion")
	line(2, "</dict>")
	line(1, "</array>")
	pair(1, "PayloadDisplayName", displayName)
	pair(1, "PayloadIdentifier", profileID)
	pair(1, "PayloadType", "Configuration")
	pair(1, "PayloadUUID", profileUUID)
	integerPair(1, "PayloadVersion")
	pair(1, "PayloadDescription", mobileConfigDescription)
	pair(1, "PayloadScope", "System")
	line(0, "</dict>")
	b.WriteString("</plist>")
	return b.String()
}

var plistEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// plistEscape escapes element text. Quotes stay as they are, like the Rust
// writer, so a byte comparison with its output holds.
func plistEscape(text string) string { return plistEscaper.Replace(text) }
