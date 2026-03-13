package dns

import (
	"context"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startMockDNSServer(t *testing.T, handler mdns.Handler) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &mdns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })

	return pc.LocalAddr().String()
}

func TestDNSCNAMEResolver_Resolve(t *testing.T) {
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "app.example.com." && r.Question[0].Qtype == mdns.TypeCNAME {
			m.Answer = append(m.Answer, &mdns.CNAME{
				Hdr:    mdns.RR_Header{Name: "app.example.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300},
				Target: "abc123.piccolospace.com.",
			})
		}
		w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler)
	resolver := NewDNSCNAMEResolver(addr, 5*time.Second)

	target, err := resolver.Resolve(context.Background(), "app.example.com")
	require.NoError(t, err)
	assert.Equal(t, "abc123.piccolospace.com", target)
}

func TestDNSCNAMEResolver_NoCNAME(t *testing.T) {
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		// Return empty answer
		w.WriteMsg(m)
	})

	addr := startMockDNSServer(t, handler)
	resolver := NewDNSCNAMEResolver(addr, 5*time.Second)

	_, err := resolver.Resolve(context.Background(), "nope.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no CNAME record found")
}

func TestDNSCNAMEResolver_Timeout(t *testing.T) {
	// Use an unreachable address to force timeout
	resolver := NewDNSCNAMEResolver("192.0.2.1:53", 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := resolver.Resolve(ctx, "app.example.com")
	assert.Error(t, err)
}
