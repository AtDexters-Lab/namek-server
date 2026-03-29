package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// ErrTXTMismatch indicates the TXT record exists but its content does not match.
type ErrTXTMismatch struct {
	FQDN     string
	Expected string
	Actual   []string
}

func (e *ErrTXTMismatch) Error() string {
	return fmt.Sprintf("txt mismatch for %s: expected %q, got %v", e.FQDN, e.Expected, e.Actual)
}

// TXTVerifier queries an authoritative DNS server to verify TXT record content.
// Used as a write-back correctness check after setting records via the PowerDNS API.
type TXTVerifier struct {
	resolver     string
	queryTimeout time.Duration
}

// NewTXTVerifier creates a verifier that queries the given DNS address.
// The address must be the authoritative PowerDNS DNS listener (not a recursive resolver).
func NewTXTVerifier(dnsAddress string, queryTimeout time.Duration) *TXTVerifier {
	return &TXTVerifier{
		resolver:     dnsAddress,
		queryTimeout: queryTimeout,
	}
}

// VerifyTXT sends a TXT query to the authoritative server and checks that the
// response contains expectedValue. Returns nil on match, *ErrTXTMismatch on
// content mismatch, or a wrapped error on query failure.
func (v *TXTVerifier) VerifyTXT(ctx context.Context, fqdn, expectedValue string) error {
	qname := mdns.Fqdn(fqdn)

	msg := new(mdns.Msg)
	msg.SetQuestion(qname, mdns.TypeTXT)
	msg.RecursionDesired = false

	client := new(mdns.Client)
	client.Timeout = v.queryTimeout

	resp, _, err := client.ExchangeContext(ctx, msg, v.resolver)
	if err != nil {
		return fmt.Errorf("dns query for %s failed: %w", fqdn, err)
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return fmt.Errorf("dns query for %s returned rcode %d", fqdn, resp.Rcode)
	}

	var allTxtValues []string
	for _, ans := range resp.Answer {
		txt, ok := ans.(*mdns.TXT)
		if !ok {
			continue
		}
		// A single TXT RR with content >255 bytes is split into multiple
		// segments by miekg/dns. Concatenate before comparing.
		var full strings.Builder
		for _, s := range txt.Txt {
			full.WriteString(unescapeTXT(s))
		}
		val := full.String()
		if val == expectedValue {
			return nil
		}
		allTxtValues = append(allTxtValues, val)
	}

	if len(allTxtValues) == 0 {
		return fmt.Errorf("no TXT records found for %s", fqdn)
	}

	return &ErrTXTMismatch{
		FQDN:     fqdn,
		Expected: expectedValue,
		Actual:   allTxtValues,
	}
}

// unescapeTXT removes DNS presentation-format backslash escapes.
// miekg/dns escapes " and \ in TXT RDATA as \" and \\ respectively.
// Note: does not handle \DDD numeric escapes — sufficient for ACME base64url
// digests which contain only [A-Za-z0-9_-].
func unescapeTXT(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s // fast path: no escapes
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++ // skip backslash, take next char literally
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
