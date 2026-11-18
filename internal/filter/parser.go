// Package filter parses blocklist formats and answers "is this domain blocked".
package filter

import "strings"

// Action says what a parsed rule does to a matching domain.
type Action uint8

const (
	ActionBlock Action = iota
	ActionAllow
)

// ParsedRule is one rule from a list. The domain is always lower case.
type ParsedRule struct {
	Domain string
	Action Action
	// IsSubdomain is true when the rule also matches every subdomain.
	IsSubdomain bool
}

var localhostEntries = map[string]struct{}{
	"localhost":             {},
	"localhost.localdomain": {},
	"local":                 {},
	"broadcasthost":         {},
	"ip6-localhost":         {},
	"ip6-loopback":          {},
	"ip6-localnet":          {},
	"ip6-mcastprefix":       {},
	"ip6-allnodes":          {},
	"ip6-allrouters":        {},
	"ip6-allhosts":          {},
}

func isLocalhostEntry(domain string) bool {
	_, found := localhostEntries[domain]
	return found
}

// looksLikeIP reports whether the line starts like a hosts-file address.
func looksLikeIP(s string) bool {
	return s != "" && (s[0] >= '0' && s[0] <= '9' || s[0] == ':')
}

// ParseLine parses one rule line. It returns false for comments, empty lines
// and lines it cannot understand.
func ParseLine(line string) (ParsedRule, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '!' {
		return ParsedRule{}, false
	}
	if rest, found := strings.CutPrefix(trimmed, "@@||"); found {
		return parseAdblock(rest, ActionAllow)
	}
	if rest, found := strings.CutPrefix(trimmed, "||"); found {
		return parseAdblock(rest, ActionBlock)
	}
	if looksLikeIP(trimmed) {
		return parseHosts(trimmed)
	}
	return parsePlainDomain(trimmed)
}

func parseAdblock(rest string, action Action) (ParsedRule, bool) {
	domain := strings.ToLower(strings.TrimSuffix(rest, "^"))
	if domain == "" || isLocalhostEntry(domain) {
		return ParsedRule{}, false
	}
	return ParsedRule{Domain: domain, Action: action, IsSubdomain: true}, true
}

func parseHosts(trimmed string) (ParsedRule, bool) {
	parts := strings.Fields(trimmed)
	if len(parts) < 2 {
		return ParsedRule{}, false
	}
	// Anything past the domain is an inline comment.
	domain := strings.ToLower(parts[1])
	if isLocalhostEntry(domain) || !strings.Contains(domain, ".") {
		return ParsedRule{}, false
	}
	return ParsedRule{Domain: domain, Action: ActionBlock}, true
}

func parsePlainDomain(trimmed string) (ParsedRule, bool) {
	if strings.Contains(trimmed, " ") || !strings.Contains(trimmed, ".") {
		return ParsedRule{}, false
	}
	domain := strings.ToLower(trimmed)
	if isLocalhostEntry(domain) {
		return ParsedRule{}, false
	}
	return ParsedRule{Domain: domain, Action: ActionBlock}, true
}

// ParseList parses a multi-line list.
func ParseList(content string) []ParsedRule {
	var rules []ParsedRule
	for len(content) > 0 {
		line, rest, _ := strings.Cut(content, "\n")
		content = rest
		if rule, ok := ParseLine(line); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}
