package dns

import (
	"context"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func txtHandler(records map[string][]string) mdns.Handler {
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		qname := r.Question[0].Name
		if vals, ok := records[qname]; ok && r.Question[0].Qtype == mdns.TypeTXT {
			m.Answer = append(m.Answer, &mdns.TXT{
				Hdr: mdns.RR_Header{Name: qname, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
				Txt: vals,
			})
		} else {
			m.Rcode = mdns.RcodeNameError
		}
		w.WriteMsg(m)
	})
}

func TestTXTVerifier_CorrectValue(t *testing.T) {
	addr := startMockDNSServer(t, txtHandler(map[string][]string{
		"_acme-challenge.host.example.com.": {"expected-digest"},
	}))

	v := NewTXTVerifier(addr, 1*time.Second)
	err := v.VerifyTXT(context.Background(), "_acme-challenge.host.example.com", "expected-digest")
	assert.NoError(t, err)
}

func TestTXTVerifier_Mismatch(t *testing.T) {
	addr := startMockDNSServer(t, txtHandler(map[string][]string{
		"_acme-challenge.host.example.com.": {"wrong-digest"},
	}))

	v := NewTXTVerifier(addr, 1*time.Second)
	err := v.VerifyTXT(context.Background(), "_acme-challenge.host.example.com", "expected-digest")
	require.Error(t, err)

	var mismatch *ErrTXTMismatch
	require.ErrorAs(t, err, &mismatch)
	assert.Equal(t, "expected-digest", mismatch.Expected)
	assert.Equal(t, []string{"wrong-digest"}, mismatch.Actual)
}

func TestTXTVerifier_NXDOMAIN(t *testing.T) {
	addr := startMockDNSServer(t, txtHandler(map[string][]string{}))

	v := NewTXTVerifier(addr, 1*time.Second)
	err := v.VerifyTXT(context.Background(), "_acme-challenge.missing.example.com", "digest")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rcode")
}

func TestTXTVerifier_Unreachable(t *testing.T) {
	v := NewTXTVerifier("192.0.2.1:53", 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := v.VerifyTXT(ctx, "_acme-challenge.host.example.com", "digest")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed")
}

func TestTXTVerifier_ContextCancelled(t *testing.T) {
	// Use an unreachable address so the context cancellation fires before the
	// DNS client timeout. Same pattern as cname_test.go TestDNSCNAMEResolver_Timeout.
	v := NewTXTVerifier("192.0.2.1:53", 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := v.VerifyTXT(ctx, "_acme-challenge.host.example.com", "digest")
	assert.Error(t, err)
}

func TestTXTVerifier_MultiSegmentTXTRecord(t *testing.T) {
	// A single TXT RR with content >255 bytes is split into multiple Txt
	// segments by miekg/dns. The verifier must concatenate them.
	part1 := "abcdefghij" // simulate a split
	part2 := "klmnopqrst"
	full := part1 + part2

	addr := startMockDNSServer(t, txtHandler(map[string][]string{
		"_acme-challenge.host.example.com.": {part1, part2},
	}))

	v := NewTXTVerifier(addr, 1*time.Second)
	err := v.VerifyTXT(context.Background(), "_acme-challenge.host.example.com", full)
	assert.NoError(t, err)
}

func TestTXTVerifier_EscapedQuoteAndBackslash(t *testing.T) {
	// miekg/dns escapes " as \" and \ as \\ in presentation format.
	// The verifier must unescape before comparing against the raw expected value.
	addr := startMockDNSServer(t, txtHandler(map[string][]string{
		"_acme-challenge.host.example.com.": {`ab\"cd\\ef`},
	}))

	v := NewTXTVerifier(addr, 1*time.Second)
	err := v.VerifyTXT(context.Background(), "_acme-challenge.host.example.com", `ab"cd\ef`)
	assert.NoError(t, err)
}

func TestTXTVerifier_NonDotTerminatedFQDN(t *testing.T) {
	addr := startMockDNSServer(t, txtHandler(map[string][]string{
		"_acme-challenge.host.example.com.": {"digest"},
	}))

	v := NewTXTVerifier(addr, 1*time.Second)
	// Pass without trailing dot — mdns.Fqdn() should normalize.
	err := v.VerifyTXT(context.Background(), "_acme-challenge.host.example.com", "digest")
	assert.NoError(t, err)
}

func TestUnescapeTXT(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no escapes", "abc123", "abc123"},
		{"escaped quote", `ab\"cd`, `ab"cd`},
		{"escaped backslash", `ab\\cd`, `ab\cd`},
		{"mixed escapes", `a\"b\\c`, `a"b\c`},
		{"trailing backslash", `abc\`, `abc\`},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, unescapeTXT(tt.input))
		})
	}
}
