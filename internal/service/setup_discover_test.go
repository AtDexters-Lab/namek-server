package service

import (
	"net"
	"testing"
)

// TestIsPrivateLANIP is the security-critical table test for the LAN-IP allowlist.
// This directly gates what a compromised device can trick a victim's browser into
// visiting via the piccolospace.com/setup discover flow. Any regression here is
// potentially a phishing or SSRF primitive.
func TestIsPrivateLANIP(t *testing.T) {
	cases := []struct {
		in      string
		want    bool
		comment string
	}{
		// RFC1918 — accept
		{"10.0.0.1", true, "RFC1918 10/8"},
		{"10.255.255.255", true, "RFC1918 10/8 edge"},
		{"172.16.0.1", true, "RFC1918 172.16/12"},
		{"172.31.255.255", true, "RFC1918 172.16/12 edge"},
		{"192.168.0.1", true, "RFC1918 192.168/16"},
		{"192.168.255.255", true, "RFC1918 192.168/16 edge"},

		// CGNAT RFC6598 — accept
		{"100.64.0.1", true, "RFC6598 CGNAT low edge"},
		{"100.127.255.254", true, "RFC6598 CGNAT high edge"},

		// RFC4193 ULA — accept
		{"fd00::1", true, "RFC4193 ULA"},
		{"fdff::1", true, "RFC4193 ULA"},

		// Public — reject
		{"8.8.8.8", false, "public Google DNS"},
		{"1.1.1.1", false, "public Cloudflare DNS"},
		{"198.51.100.42", false, "TEST-NET-2 documentation"},
		{"203.0.113.7", false, "TEST-NET-3 documentation"},
		{"2001:db8::1", false, "IPv6 documentation"},

		// Link-local — REJECT (closes 169.254.169.254 IMDS SSRF variant)
		{"169.254.1.1", false, "IPv4 link-local RFC3927"},
		{"169.254.169.254", false, "CRITICAL: AWS/GCP IMDS endpoint"},
		{"fe80::1", false, "IPv6 link-local RFC4291"},

		// CGNAT edges — reject just outside
		{"100.63.255.255", false, "just below CGNAT range"},
		{"100.128.0.0", false, "just above CGNAT range"},

		// Loopback — reject
		{"127.0.0.1", false, "IPv4 loopback"},
		{"127.1.2.3", false, "IPv4 loopback 127/8"},
		{"::1", false, "IPv6 loopback"},

		// Unspecified / multicast — reject
		{"0.0.0.0", false, "IPv4 unspecified"},
		{"224.0.0.1", false, "IPv4 multicast"},
		{"ff00::1", false, "IPv6 multicast"},

		// IPv4-mapped IPv6 — accept private, reject public
		{"::ffff:10.0.0.5", true, "IPv4-mapped private"},
		{"::ffff:8.8.8.8", false, "IPv4-mapped public"},
	}

	for _, tc := range cases {
		t.Run(tc.in+"/"+tc.comment, func(t *testing.T) {
			ip := net.ParseIP(tc.in)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", tc.in)
			}
			got := isPrivateLANIP(ip)
			if got != tc.want {
				t.Errorf("isPrivateLANIP(%q) = %v, want %v (%s)", tc.in, got, tc.want, tc.comment)
			}
		})
	}
}

func TestIsPrivateLANIP_Nil(t *testing.T) {
	if isPrivateLANIP(nil) {
		t.Error("isPrivateLANIP(nil) should be false")
	}
}
