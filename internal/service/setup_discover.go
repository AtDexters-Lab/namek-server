package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/metrics"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

// ErrInvalidLANIP is returned by UpdateSetupHeartbeat when a submitted IP is not
// within an accepted private/LAN range. The underlying error wraps the offending
// entry so the handler can produce a helpful 400 response.
var ErrInvalidLANIP = errors.New("invalid lan ip")

const maxSetupLANIPs = 10

// UpdateSetupHeartbeat validates and persists a setup-mode heartbeat from a TPM-
// authenticated device. On setupComplete=true the record is cleared so the device
// drops out of discover results immediately; the terminal heartbeat may omit
// lan_ips entirely. On setupComplete=false the LAN IP list is required and must
// contain only private ranges (RFC1918 / RFC6598 CGNAT / RFC4193 ULA) — public,
// link-local, loopback, multicast, and unspecified are rejected here.
func (s *DeviceService) UpdateSetupHeartbeat(ctx context.Context, deviceID uuid.UUID, clientIP net.IP, lanIPs []string, setupComplete bool) error {
	// Ongoing heartbeats must carry between 1 and maxSetupLANIPs valid private IPs.
	// The terminal setup_complete=true heartbeat is allowed to carry none — in that
	// case we just clear the row. Any IPs submitted alongside setup_complete=true
	// are still validated and canonicalized, so a client cannot slip past the
	// allowlist by flipping the flag.
	if !setupComplete && len(lanIPs) < 1 {
		return fmt.Errorf("%w: lan_ips must not be empty when setup_complete=false", ErrInvalidLANIP)
	}
	if len(lanIPs) > maxSetupLANIPs {
		return fmt.Errorf("%w: lan_ips count must be <= %d (got %d)", ErrInvalidLANIP, maxSetupLANIPs, len(lanIPs))
	}
	// Canonicalize as we validate — store v4 addresses in their canonical dotted
	// form so the frontend never receives oddities like "::ffff:10.0.0.5".
	canonical := make([]string, 0, len(lanIPs))
	for _, raw := range lanIPs {
		parsed := net.ParseIP(raw)
		if parsed == nil {
			return fmt.Errorf("%w: %q is not a valid IP", ErrInvalidLANIP, raw)
		}
		if !isPrivateLANIP(parsed) {
			return fmt.Errorf("%w: %q is not in an accepted private LAN range", ErrInvalidLANIP, raw)
		}
		if v4 := parsed.To4(); v4 != nil {
			canonical = append(canonical, v4.String())
		} else {
			canonical = append(canonical, parsed.String())
		}
	}

	res, err := s.deviceStore.UpdateSetupHeartbeat(ctx, deviceID, clientIP, canonical, setupComplete)
	if err != nil {
		return fmt.Errorf("update setup heartbeat: %w", err)
	}
	if res.RowsAffected == 0 {
		// The auth middleware already validated the device exists; a zero-rows
		// result here means the row was deleted (or renamed) in the narrow
		// window between DeviceTPMAuth and this handler. Self-healing — the
		// next request from this deviceID will 401 at the auth middleware.
		// Observable via this counter so sustained hits surface a problem.
		metrics.Get().SetupDiscover.HeartbeatGuardRejected.Add(1)
		s.logger.Warn("heartbeat landed on missing device row",
			"device_id", deviceID,
			"setup_complete", setupComplete,
		)
	}
	return nil
}

// DiscoverSetupDevices returns setup-mode devices whose last recorded public IP
// matches the caller's. TTL is operator-configurable (default 120s); devices that
// miss three 30s heartbeats age out naturally.
func (s *DeviceService) DiscoverSetupDevices(ctx context.Context, callerIP net.IP, ttl time.Duration) ([]store.SetupDeviceResult, error) {
	return s.deviceStore.FindSetupDevicesByPublicIP(ctx, callerIP, ttl)
}

// isPrivateLANIP decides whether a device-reported IP is acceptable as a LAN
// address. The rejection of link-local is critical — it closes the
// 169.254.169.254 cloud-metadata SSRF phishing variant documented in the plan.
//
// Accept:
//   - RFC1918 (10/8, 172.16/12, 192.168/16) via stdlib IsPrivate()
//   - RFC4193 ULA (fc00::/7) also via stdlib IsPrivate()
//   - RFC6598 CGNAT (100.64.0.0/10) via manual check — stdlib does not cover this
//
// Reject everything else (public, link-local v4/v6, loopback, multicast, unspecified).
func isPrivateLANIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// RFC6598: 100.64.0.0/10 — second octet in [64, 127].
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}
