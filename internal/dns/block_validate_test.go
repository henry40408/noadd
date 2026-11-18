package dns

import "testing"

func TestValidBlockModeAcceptsExactNamesIgnoringSurroundingSpace(t *testing.T) {
	for _, raw := range []string{"null_ip", "nxdomain", "refused", "custom_ip", "  refused\n"} {
		if !ValidBlockMode(raw) {
			t.Errorf("ValidBlockMode(%q) = false", raw)
		}
	}
	for _, raw := range []string{"", "NXDOMAIN", "null", "custom"} {
		if ValidBlockMode(raw) {
			t.Errorf("ValidBlockMode(%q) = true", raw)
		}
	}
}

func TestValidCustomIPsRequireTheirOwnFamily(t *testing.T) {
	if !ValidCustomIPv4(" 192.0.2.1 ") || ValidCustomIPv4("2001:db8::1") || ValidCustomIPv4("not-an-ip") || ValidCustomIPv4("") {
		t.Error("ValidCustomIPv4 misclassified an input")
	}
	if !ValidCustomIPv6(" 2001:db8::1 ") || ValidCustomIPv6("192.0.2.1") || ValidCustomIPv6("not-an-ip") || ValidCustomIPv6("") {
		t.Error("ValidCustomIPv6 misclassified an input")
	}
}
