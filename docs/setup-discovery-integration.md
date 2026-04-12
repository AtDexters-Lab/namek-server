# Setup Discovery Integration Spec

Spec for integrating piccolod and piccolospace with namek-server's mDNS-fallback setup discovery flow. Ships in namek-server tag `v0.2.0`.

## 1. Problem

When a user boots a Piccolo for the first time, the intended UX is to reach `piccolo-xyz.local` via mDNS. mDNS fails on:

- Corporate and enterprise firewalls that drop multicast
- Some consumer routers with broken IGMP snooping
- Windows hosts that never bother with mDNS at all
- Any network that isolates clients from each other (hotel Wi-Fi, some mobile hotspots)

Users on those networks currently have no fallback except typing raw IPs. The setup discovery flow closes that hole: the device registers its LAN IPs with namek, and the browser asks namek "any setup-mode devices on my public IP?". Namek answers yes/no based on who else is NATed behind the same external address.

## 2. Flow

```
Device boots
    |
    | 1. Auto-enroll via TPM attestation (existing)
    |    - Hardware model shipped in the attest body
    |
    v
Device detects setup-not-complete → starts setup heartbeat loop
    |
    | 2. Every 30s: POST /api/v1/devices/me/heartbeat
    |    body: {"lan_ips": [...], "setup_complete": false}
    |    (Server records setup_heartbeat_at, lan_ips, ip_address)
    |
    v
User visits picolospace.com/setup
    |
    | 3. Frontend polls GET /api/v1/setup/discover every 3s
    |    (Namek matches caller's public IP against setup-mode devices,
    |     2-minute TTL)
    |
    v
Response contains hardware_model + lan_ips
    |
    | 4. Frontend renders the device list with a verification affordance
    |    (see §6) and lets the user click through to http://<lan_ip>
    |
    v
User completes setup on the device's web UI
    |
    | 5. Device sends final POST /devices/me/heartbeat
    |    body: {"lan_ips": [], "setup_complete": true}
    |    (Server clears setup_heartbeat_at and lan_ips → device
    |     disappears from discover)
    v
```

LAN reachability is the proof of physical possession. Relay-only setup was rejected: it cannot prove the caller is actually on the same network, only that they share a public IP.

## 3. Server-Side Contract

### New endpoints

#### POST /api/v1/devices/me/heartbeat (TPM-authenticated)

Device publishes (or clears) its setup-mode LAN footprint. TPM-authenticated via the existing `deviceAuth` group — requires `X-Device-ID`, `X-Nonce`, `X-TPM-Quote` headers just like the other device endpoints.

**Request:**
```json
{
  "lan_ips": ["10.0.0.5", "192.168.1.7"],
  "setup_complete": false
}
```

Field rules:

| Field | Type | Required | Notes |
|---|---|---|---|
| `lan_ips` | `string[]` | **Only when `setup_complete=false`** | 1–10 entries. Each must parse as an IP and be in an accepted private range (see §5). On `setup_complete=true` this field may be omitted or empty; any submitted entries are still validated. |
| `setup_complete` | `bool` | yes | `false` for ongoing heartbeats. `true` for the terminal heartbeat that clears the row. |

**Response:** `204 No Content`

**Errors:**
| Status | Meaning |
|---|---|
| 400 | Invalid body — `lan_ips` empty when `setup_complete=false`, more than 10 entries, non-parseable IP, or an entry outside the accepted private ranges |
| 401 | TPM quote verification failed |
| 429 | Per-device mutation rate limit exceeded (60/min default) |
| 500 | Store failure |

**Server-side guarantees on every accepted heartbeat:**

1. `ip_address`, `lan_ips`, and `setup_heartbeat_at` are updated atomically in a single `UPDATE` statement. The downstream discover query sees a consistent snapshot with no `LastSeenBatcher` flush lag.
2. `lan_ips` entries that arrive as IPv4-mapped IPv6 (`::ffff:10.0.0.5`) are canonicalized to dotted-quad before storage, so the frontend never has to handle the v6-wrapped form.
3. `RowsAffected == 0` is treated as a non-error and returns `204`. It only happens if the device row was deleted or suspended in the narrow window between auth middleware and this handler. Observability signal: `metrics.SetupDiscover.HeartbeatGuardRejected`.

#### GET /api/v1/setup/discover (unauthenticated, CORS-gated, rate-limited)

Returns setup-mode devices whose last recorded public IP matches the caller's. Intended for `picolospace.com/setup` to poll from the browser.

**Response:**
```json
{
  "devices": [
    {
      "hardware_model": "Raspberry Pi 4 Model B Rev 1.5",
      "lan_ips": ["10.0.0.5", "192.168.1.7"]
    }
  ]
}
```

- Empty array (`{"devices": []}`) when no match — **never 404**.
- `hostname` is deliberately **not** returned. Reducing fingerprinting surface on CGNAT neighbourhoods.
- Rate limit: 500 rps global / 10 rps per-IP / burst 30 per-IP. All operator-tunable via `setupDiscover.*` in server config.
- TTL: 120 seconds. Devices that miss three 30s heartbeats drop out.

**Response headers:**
| Header | Value | Purpose |
|---|---|---|
| `Cache-Control` | `no-store, private` | Prevents future shared caches / CDNs from replaying one caller's device list to another |
| `Vary` | `Origin` | Set unconditionally, safe for future CORS-varying caches |
| `Access-Control-Allow-Origin` | Caller `Origin` if allowlisted | Default allowlist: `https://piccolospace.com`, `https://www.piccolospace.com`. Operator-configurable |

**Errors:**
| Status | Meaning |
|---|---|
| 400 | Malformed `Origin` header or client IP (extremely rare) |
| 429 | Rate limit exceeded — respect `Retry-After` |
| 500 | Store failure |

### Extension to existing enrollment

`POST /api/v1/devices/enroll/attest` accepts an optional `hardware_model` field in the request body. Capped at 128 characters, optional (omit is fine), flows through both the first-enroll and re-enroll paths. Old clients that never send it continue to work; the column stays NULL.

Re-enrollment with a new `hardware_model` string updates the stored value via a dedicated `UpdateHardwareModel` store method, not via `UpdateTrustData` — so the operator-facing `ClearTrustOverride` flow is unaffected.

## 4. Piccolod Integration

### namekclient symbols (added in v0.2.0)

```go
import "github.com/AtDexters-Lab/namek-server/pkg/namekclient"

// 1. Construct the client with the hardware model you want to publish.
client := namekclient.New(
    namekURL,
    tpmDevice,
    namekclient.WithHardwareModel("Raspberry Pi 4 Model B Rev 1.5"),
)

// 2. Enroll as before. The hardware model ships as part of the attest body.
result, err := client.Enroll(ctx)
// or client.EnrollWithRecovery(ctx, bundle) — both paths propagate the model.

// 3. Start a heartbeat loop while setup is incomplete.
err := client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
    LANIPs:        collectLANIPs(),
    SetupComplete: false,
})

// 4. When setup completes, send the terminal heartbeat.
err := client.SendHeartbeat(ctx, &namekclient.HeartbeatRequest{
    SetupComplete: true,   // lan_ips may be nil/empty here
})
```

### Loop invariants piccolod must honor

1. **Heartbeat every 30 seconds** while setup is incomplete. The server TTL is 120s, so three missed heartbeats drop the device out of discover.
2. **Collect LAN IPs from non-loopback, non-link-local IPv4 interfaces.** Do not submit IPv6 link-local (`fe80::/10`), IPv4 link-local (`169.254.0.0/16`), loopback, multicast, or public addresses. The server rejects all of these with 400 and you burn a TPM quote for nothing.
3. **Completion must be the final heartbeat.** If a delayed in-flight heartbeat from a prior retry arrives AFTER the `setup_complete=true` write, the device flips back into discover for up to one TTL window. The loop must tear down its ticker and cancel in-flight requests before sending completion.
4. **Stop heartbeating on `isSetupComplete() == true`**, including the fail-safe path: if the persistence layer errors while checking completion, treat that as "complete" and stop — otherwise a locked persistence layer keeps the device visible to strangers indefinitely.
5. **Initial delay of 10 seconds** after enrollment before the first heartbeat, to stagger with endpoint sync and avoid bursting the per-device rate limit.
6. **Skip the tick** if `collectLANIPs()` returns empty — don't send a heartbeat the server will reject.

### namekclient behavioral changes in v0.2.0

Pre-existing callers should be aware:

- The embedded `*http.Client` now installs a `CheckRedirect` policy that rejects all 3xx responses. Go's default client silently drops POST bodies on POST→GET redirects, which would turn heartbeats into empty requests against whatever the redirect target is. If any existing caller depends on following redirects through namekclient, that caller breaks.
- `namekclient.WithHTTPClient(hc)` now **shallow-copies** `hc` before installing `CheckRedirect`. A caller that was sharing a single `*http.Client` across services and expected later mutations to `hc.Timeout` (or similar) to propagate into namekclient will not see those mutations anymore. This is the correct behavior — namekclient never should have been mutating caller-owned clients — but it is a subtle break worth flagging.

### Heartbeat cost

Each heartbeat is 1 nonce fetch + 1 TPM quote + 1 POST = 2 HTTP round-trips. At 30s cadence that is 2 mutations/min per device, well under the 60/min device mutation budget.

## 5. `lan_ips` Validation (authoritative)

Server-side accept list:

- RFC 1918 — `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (stdlib `net.IP.IsPrivate()`)
- RFC 4193 — `fc00::/7` IPv6 unique local (also `net.IP.IsPrivate()`)
- RFC 6598 — `100.64.0.0/10` CGNAT (manual check; stdlib does not cover this)

Server-side reject list:

- All public IPv4 and IPv6
- IPv4 link-local `169.254.0.0/16` — **critical**, this closes the `169.254.169.254` cloud-metadata SSRF phishing variant
- IPv6 link-local `fe80::/10`
- Loopback (`127.0.0.0/8`, `::1`)
- Multicast (`224.0.0.0/4`, `ff00::/8`)
- Unspecified (`0.0.0.0`, `::`)

Validation source of truth: `isPrivateLANIP()` in `internal/service/setup_discover.go`. Covered by 34 unit test cases in the same package.

## 6. Piccolospace (Frontend) Integration

The frontend polls discover and renders the result. Three contracts apply.

### Polling loop

- Hit `GET https://namek.piccolospace.com/api/v1/setup/discover` on page load and every 3 seconds thereafter.
- Do **not** send `credentials: 'include'`. The endpoint is unauthenticated and sets no cookies; sending credentials would force the server into a weaker CORS mode.
- On `429`, **respect `Retry-After`**. Default per-IP limit is 10 rps / burst 30; legitimate polling (≈0.33 rps) never hits it, but manual refreshes and retry bursts can. Tight-looping on 429 will break the flow for the whole CGNAT cohort behind the user's IP.
- If the poll interval changes (e.g. tighter than 3s), coordinate with the namek-server team before rolling out. The per-IP rate limit is sized to the current cadence.

### Rendering discovered devices

- The response shape is `{"devices": [{"hardware_model": "...", "lan_ips": [...]}]}`. Empty array means "no setup-mode device on your public IP right now" — show the "searching" state, not an error.
- **Do not** render the device's first LAN IP as a blind `<a href="http://10.0.0.5/">Connect</a>`. Even with the server's private-range validation, a compromised device can still advertise plausible gateway IPs (`192.168.1.1`, `10.0.0.1`) that would redirect the user at their own router admin panel or another LAN-resident device.
- **Recommended UX** (advisory, not enforced): render the IP as text with a clear "This is the address your Piccolo reported — verify it matches what the device's own screen shows before clicking" explainer. Or a two-step click (show → confirm → navigate). Goal: keep the user in the loop before browser navigation.

### Error states

| Situation | Suggested UX |
|---|---|
| Discover returns `[]` for > 60 seconds | Show the troubleshooting block: "Make sure your Piccolo is powered on and connected to the internet / If you're using a VPN, try disconnecting and refreshing / Try accessing it directly at `http://piccolo.local`" |
| Discover returns 429 | Honor `Retry-After`. Display a silent wait; don't alarm the user |
| Discover returns 5xx | "Can't reach namek — try again shortly." Retry with exponential backoff |
| CORS failure (browser blocks the response) | Means the frontend is running on an origin not in the server allowlist. File an issue with the namek-server team to add the origin |

## 7. Rollout Steps

1. **namek-server** — merged on `main`. Pending: 48-hour staging soak (see §8 for exit criteria), then `git tag v0.2.0`.
2. **piccolod** — update `go.mod` to `github.com/AtDexters-Lab/namek-server@v0.2.0` after the soak. Implement the heartbeat loop per §4. No coordination with the namek-server team required beyond the tag.
3. **piccolospace** — implement the polling page per §6. Point at `https://namek.piccolospace.com/api/v1/setup/discover`. Can deploy as soon as namek-server is on main (the endpoint will be live).

Order independence: piccolospace and piccolod do not need to ship simultaneously. The server endpoint is additive; piccolod can adopt on its own timeline; piccolospace can ship before piccolod and just show an empty discover list until devices start heartbeating.

## 8. Operational Notes

### 48-hour pre-tag staging soak

Run against a canary device on staging before tagging `v0.2.0`. Exit criteria (all must hold):

- Zero `metrics.SetupDiscover.Errors` over the window
- Zero `metrics.SetupDiscover.HeartbeatGuardRejected` events (sustained non-zero would indicate a device-deletion race — investigate)
- Zero new `metrics.LastSeen.FlushErrors` attributable to the batcher monotonic guard change
- `metrics.SetupDiscover.Matched + NoMatch` grows at the expected cadence from the canary
- `/metrics` scrape latency p99 unchanged vs. pre-deploy baseline
- No new `ERROR`-level log entries on `setup_discover` or `device_heartbeat` code paths

### Migration v5

- Adds `hardware_model TEXT`, `lan_ips TEXT[]`, `setup_heartbeat_at TIMESTAMPTZ` to `devices`.
- Adds a partial index: `CREATE INDEX idx_devices_setup_discovery ON devices(ip_address) WHERE setup_heartbeat_at IS NOT NULL`.
- Runs inside a single transaction, so `CREATE INDEX CONCURRENTLY` is not used. Safe at the current `devices` table size (sub-second build); schedule during a low-traffic window as a precaution.
- Rollback is safe: the new columns are nullable, so an old binary that doesn't know about them continues to operate.

### Acknowledged risks (non-blocking)

1. **Residual LAN-IP-class SSRF** — a compromised device advertising `192.168.1.1` can still redirect a victim's browser at their own router admin panel. Mitigation lives in the piccolospace rendering requirement (§6).
2. **Enterprise NAT > 30 concurrent setup users** — 30 concurrent polls × 0.33 rps = 10 rps, exactly the per-IP steady-state cap. Graceful degradation (Retry-After honored), not failure. Operator-tunable per deployment.
3. **Dual-stack IP-family mismatch** — if the device heartbeats over IPv4 and the browser reaches namek over IPv6 (or vice versa), discover returns empty. The server tracks only one `ip_address` per device. Follow-up: add a secondary `ip_address_alt` column if this becomes a real pain point.
4. **Stale in-flight heartbeat flipping device back after completion** — mitigated by the piccolod loop invariant in §4.3 (completion must be the final heartbeat sent).

## 9. References

- Implementation: `git log --grep='setup discovery endpoint'` on `main`
- Plan: `~/.claude/plans/cheeky-shimmying-shamir.md` (internal)
- Original cross-repo RFC: `~/.claude/plans/purring-launching-blanket.md` (internal, authored by piccolod team)
- Piccolod integration reference: [piccolod-integration-spec.md](piccolod-integration-spec.md)
- Test coverage:
  - `tests/integration/setup_discovery_test.go` — 13 end-to-end tests against real Postgres + swtpm
  - `internal/store/last_seen_batcher_integration_test.go` — batcher monotonic-guard regression
  - `internal/service/setup_discover_test.go` — `isPrivateLANIP` table test (34 cases)
  - `internal/auth/cors_test.go` — CORS middleware
  - `pkg/namekclient/heartbeat_test.go` — namekclient enroll + heartbeat + redirect handling
