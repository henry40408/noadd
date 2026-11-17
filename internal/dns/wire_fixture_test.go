package dns

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

type wireCase struct {
	Name     string            `json:"name"`
	Settings map[string]string `json:"settings"`
	Steps    []wireStep        `json:"steps"`
}

type wireStep struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Upstream *struct {
		Response string `json:"response"`
	} `json:"upstream"`
}

func loadWireCases(t *testing.T) []wireCase {
	t.Helper()
	paths, err := filepath.Glob("testdata/wire/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no wire fixtures: %v", err)
	}
	var cases []wireCase
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var c wireCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		cases = append(cases, c)
	}
	return cases
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// synthesize is the part of the handler that answers without asking upstream.
// The rule set of the block fixtures is ads.example.com blocked, with
// ok.ads.example.com allowed. ok is false when the case needs the forwarder.
func synthesize(query []byte, settings map[string]string) (response []byte, ok bool) {
	msg := new(mdns.Msg)
	if msg.Unpack(query) != nil {
		return BuildServfail(query), true
	}
	if msg.Opcode != mdns.OpcodeQuery {
		response, _ = BuildNotimp(msg)
		return response, true
	}
	if opt := msg.IsEdns0(); opt != nil && opt.Version() > 0 {
		response, _ = BuildBadvers(msg)
		return response, true
	}
	if len(msg.Question) == 0 {
		return BuildServfail(query), true
	}
	name := strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
	if name != "ads.example.com" {
		return nil, false
	}
	config := BlockConfigFromSettings(settings["block_mode"], settings["block_custom_ipv4"], settings["block_custom_ipv6"])
	response, _ = BuildBlocked(msg, config)
	return response, true
}

// Every Rust response that was produced without upstream must be reproduced
// byte for byte: these helpers build all of them.
func TestSynthesizedResponsesMatchRust(t *testing.T) {
	checked := 0
	for _, c := range loadWireCases(t) {
		for _, step := range c.Steps {
			if step.Upstream != nil || step.Response == "" {
				continue
			}
			got, ok := synthesize(mustHex(t, step.Request), c.Settings)
			if !ok {
				continue
			}
			checked++
			if want := mustHex(t, step.Response); !bytes.Equal(got, want) {
				t.Errorf("%s:\n got  %x\n want %x", c.Name, got, want)
			}
		}
	}
	if checked < 45 {
		t.Fatalf("only %d synthesized fixtures were compared", checked)
	}
}

// The upstream answers of the truncation fixtures, shortened for a UDP client,
// must carry the same TC bit, question and OPT as the Rust answer.
func TestTruncationMatchesRustSemantics(t *testing.T) {
	checked := 0
	for _, c := range loadWireCases(t) {
		if !strings.HasPrefix(c.Name, "truncate_udp_") {
			continue
		}
		step := c.Steps[0]
		query, want := mustHex(t, step.Request), mustUnpack(t, mustHex(t, step.Response))
		got := mustUnpack(t, TruncateForUDP(query, mustHex(t, step.Upstream.Response)))
		checked++
		if got.Truncated != want.Truncated || len(got.Answer) != len(want.Answer) || len(got.Question) != len(want.Question) {
			t.Errorf("%s: TC %v/%v answers %d/%d", c.Name, got.Truncated, want.Truncated, len(got.Answer), len(want.Answer))
		}
		// Stripping the OPT for a plain client is the handler's job, before truncation.
		clientUsesEDNS := mustUnpack(t, query).IsEdns0() != nil
		if clientUsesEDNS && (got.IsEdns0() == nil) != (want.IsEdns0() == nil) {
			t.Errorf("%s: OPT presence differs", c.Name)
		}
	}
	if checked == 0 {
		t.Fatal("no truncation fixtures found")
	}
}

// TTLOffsets must locate the TTL the parser reads in every recorded response.
func TestTTLOffsetsOnRecordedResponses(t *testing.T) {
	for _, c := range loadWireCases(t) {
		for _, step := range c.Steps {
			if step.Response == "" {
				continue
			}
			wire := mustHex(t, step.Response)
			msg := new(mdns.Msg)
			if msg.Unpack(wire) != nil {
				continue
			}
			var want []uint32
			for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
				for _, record := range section {
					if record.Header().Rrtype != mdns.TypeOPT {
						want = append(want, record.Header().Ttl)
					}
				}
			}
			var got []uint32
			for _, offset := range TTLOffsets(wire) {
				got = append(got, ttlAt(wire, int(offset)))
			}
			if len(got) != len(want) {
				t.Errorf("%s: %d offsets for %d records", c.Name, len(got), len(want))
				continue
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("%s: TTL %d at offset = %d, parser reads %d", c.Name, i, got[i], want[i])
				}
			}
		}
	}
}
