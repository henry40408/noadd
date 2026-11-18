package dnsserver

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestSummarizeRecordNamesEachRecordTypeByItsTarget(t *testing.T) {
	header := func(rrtype uint16) mdns.RR_Header {
		return mdns.RR_Header{Name: "example.com.", Rrtype: rrtype, Class: mdns.ClassINET, Ttl: 60}
	}
	cases := []struct {
		record mdns.RR
		want   string
	}{
		{&mdns.AAAA{Hdr: header(mdns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")}, "2001:db8::1"},
		{&mdns.CNAME{Hdr: header(mdns.TypeCNAME), Target: "t.example.com."}, "t.example.com."},
		{&mdns.NS{Hdr: header(mdns.TypeNS), Ns: "ns1.example.com."}, "ns1.example.com."},
		{&mdns.PTR{Hdr: header(mdns.TypePTR), Ptr: "host.example.com."}, "host.example.com."},
		{&mdns.SOA{Hdr: header(mdns.TypeSOA), Ns: "ns1.example.com.", Mbox: "admin.example.com."}, "ns1.example.com. admin.example.com."},
		{&mdns.CAA{Hdr: header(mdns.TypeCAA), Tag: "issue", Value: "ca.example"}, "issue ca.example"},
	}
	for _, tc := range cases {
		if got := summarizeRecord(tc.record); got != tc.want {
			t.Errorf("summarizeRecord(%T) = %q, want %q", tc.record, got, tc.want)
		}
	}
}

func TestSummarizeRecordFallsBackToRdataText(t *testing.T) {
	record := &mdns.HINFO{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeHINFO, Class: mdns.ClassINET, Ttl: 60},
		Cpu: "amd64", Os: "linux",
	}
	if got := summarizeRecord(record); got != `"amd64" "linux"` {
		t.Fatalf("summary = %q", got)
	}
}

func TestResultSummaryIgnoresUnparseableWire(t *testing.T) {
	if got := resultSummary([]byte{1, 2, 3}); got != "" {
		t.Fatalf("summary = %q, want empty", got)
	}
}
