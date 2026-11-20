package dnsserver

import (
	"strconv"
	"strings"

	mdns "github.com/miekg/dns"
)

const maxSummarizedAnswers = 3

// queryTypeNames are the record types named in the query log. Any other type
// is logged as "Unknown".
var queryTypeNames = map[uint16]string{
	1: "A", 28: "AAAA", 65305: "ANAME", 255: "ANY", 251: "IXFR", 252: "AXFR",
	257: "CAA", 59: "CDS", 60: "CDNSKEY", 37: "CERT", 5: "CNAME", 62: "CSYNC",
	39: "DNAME", 48: "DNSKEY", 43: "DS", 13: "HINFO", 65: "HTTPS", 25: "KEY",
	15: "MX", 35: "NAPTR", 2: "NS", 47: "NSEC", 50: "NSEC3", 51: "NSEC3PARAM",
	10: "NULL", 61: "OPENPGPKEY", 41: "OPT", 12: "PTR", 46: "RRSIG", 24: "SIG",
	53: "SMIMEA", 6: "SOA", 33: "SRV", 44: "SSHFP", 64: "SVCB", 52: "TLSA",
	250: "TSIG", 16: "TXT", 0: "ZERO",
}

func queryTypeName(queryType uint16) string {
	if name, ok := queryTypeNames[queryType]; ok {
		return name
	}
	return "Unknown"
}

// resultSummary describes the first three answer records as a comma-separated
// string for the query log's result column. It returns "" when there is
// nothing to summarize.
func resultSummary(responseBytes []byte) string {
	response := new(mdns.Msg)
	if response.Unpack(responseBytes) != nil {
		return ""
	}
	parts := make([]string, 0, maxSummarizedAnswers)
	for _, record := range response.Answer[:min(len(response.Answer), maxSummarizedAnswers)] {
		parts = append(parts, summarizeRecord(record))
	}
	return strings.Join(parts, ", ")
}

func summarizeRecord(record mdns.RR) string {
	switch rr := record.(type) {
	case *mdns.A:
		return rr.A.String()
	case *mdns.AAAA:
		return rr.AAAA.String()
	case *mdns.CNAME:
		return rr.Target
	case *mdns.MX:
		return strconv.Itoa(int(rr.Preference)) + " " + rr.Mx
	case *mdns.NS:
		return rr.Ns
	case *mdns.PTR:
		return rr.Ptr
	case *mdns.TXT:
		return strings.Join(rr.Txt, "")
	case *mdns.SOA:
		return rr.Ns + " " + rr.Mbox
	case *mdns.SRV:
		return rr.Target + ":" + strconv.Itoa(int(rr.Port)) + " p=" + strconv.Itoa(int(rr.Priority)) + " w=" + strconv.Itoa(int(rr.Weight))
	case *mdns.CAA:
		return rr.Tag + " " + rr.Value
	}
	return strings.TrimPrefix(record.String(), record.Header().String())
}
