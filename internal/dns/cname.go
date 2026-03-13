package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// CNAMEResolver resolves CNAME records for a given domain.
type CNAMEResolver interface {
	Resolve(ctx context.Context, domain string) (string, error)
}

// DNSCNAMEResolver queries CNAME records directly using miekg/dns.
type DNSCNAMEResolver struct {
	resolver string
	timeout  time.Duration
}

// NewDNSCNAMEResolver creates a CNAME resolver. If resolver is empty, it reads
// the system's /etc/resolv.conf to determine the default DNS server.
func NewDNSCNAMEResolver(resolver string, timeout time.Duration) *DNSCNAMEResolver {
	if resolver == "" {
		resolver = systemResolver()
	}
	return &DNSCNAMEResolver{
		resolver: resolver,
		timeout:  timeout,
	}
}

func systemResolver() string {
	cfg, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		server := cfg.Servers[0]
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		// IPv6 addresses contain colons; wrap in brackets for host:port
		if strings.Contains(server, ":") {
			return "[" + server + "]:" + port
		}
		return server + ":" + port
	}
	return "127.0.0.1:53"
}

func (r *DNSCNAMEResolver) Resolve(ctx context.Context, domain string) (string, error) {
	fqdn := mdns.Fqdn(domain)

	msg := new(mdns.Msg)
	msg.SetQuestion(fqdn, mdns.TypeCNAME)
	msg.RecursionDesired = true

	client := new(mdns.Client)
	client.Timeout = r.timeout

	resp, _, err := client.ExchangeContext(ctx, msg, r.resolver)
	if err != nil {
		return "", fmt.Errorf("dns query failed: %w", err)
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return "", fmt.Errorf("dns query returned rcode %d", resp.Rcode)
	}

	for _, ans := range resp.Answer {
		if cname, ok := ans.(*mdns.CNAME); ok {
			// Remove trailing dot from FQDN
			target := cname.Target
			if len(target) > 0 && target[len(target)-1] == '.' {
				target = target[:len(target)-1]
			}
			return target, nil
		}
	}

	return "", fmt.Errorf("no CNAME record found for %s", domain)
}
