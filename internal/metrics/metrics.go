package metrics

import (
	"sync/atomic"
	"time"
)

var global = NewCollector()

// Get returns the global metrics collector.
func Get() *Collector { return global }

// Collector holds all operational metrics as atomic counters.
// Counters are monotonic from process start and reset on restart.
type Collector struct {
	StartedAt time.Time

	HTTP      HTTPMetrics
	RateLimit RateLimitMetrics
	Enroll    EnrollMetrics
	Nonce     NonceMetrics
	DNS       DNSMetrics
	ACME      ACMEMetrics
	LastSeen  LastSeenMetrics
	Census    CensusMetrics
	Nexus     NexusMetrics
	Recovery  RecoveryMetrics
}

// NewCollector creates a fresh collector with StartedAt set to now.
func NewCollector() *Collector {
	return &Collector{StartedAt: time.Now()}
}

// Reset replaces the global collector with a fresh instance. For testing.
func Reset() { global = NewCollector() }

type HTTPMetrics struct {
	Requests2xx atomic.Int64
	Requests4xx atomic.Int64
	Requests429 atomic.Int64
	Requests5xx atomic.Int64
}

type RateLimitMetrics struct {
	RejectedGlobal    atomic.Int64
	RejectedPerIP     atomic.Int64
	RejectedPerDevice atomic.Int64
}

type EnrollMetrics struct {
	Phase1Started          atomic.Int64
	Phase1CapacityExceeded atomic.Int64
	Phase2Completed        atomic.Int64
	Phase2Failed           atomic.Int64
	Reenrolled             atomic.Int64
}

type NonceMetrics struct {
	CapacityRejected atomic.Int64
	ConsumeNotFound  atomic.Int64
}

type DNSMetrics struct {
	UDPQueries atomic.Int64
	TCPQueries atomic.Int64
	UDPDropped atomic.Int64
	TCPDropped atomic.Int64
	Errors     atomic.Int64
}

type ACMEMetrics struct {
	ChallengesCreated atomic.Int64
	ChallengesDeleted atomic.Int64
	ChallengesExpired atomic.Int64
	DNSSetFailed      atomic.Int64
	VerifyOK          atomic.Int64
	VerifyFailed      atomic.Int64
}

type LastSeenMetrics struct {
	FlushSuccess   atomic.Int64
	FlushErrors    atomic.Int64
	EntriesDropped atomic.Int64
}

type CensusMetrics struct {
	RunsCompleted   atomic.Int64
	RunsFailed      atomic.Int64
	LastCompletedAt atomic.Int64 // unix seconds
	LastDurationMs  atomic.Int64
}

type NexusMetrics struct {
	Registered     atomic.Int64
	Reactivated    atomic.Int64
	MarkedInactive atomic.Int64
}

type RecoveryMetrics struct {
	ClaimsSubmitted   atomic.Int64
	QuorumReached     atomic.Int64
	AccountsDissolved atomic.Int64
}

// Snapshot returns a JSON-serializable copy of all current counter values.
func (c *Collector) Snapshot() Snapshot {
	return Snapshot{
		HTTP: HTTPSnapshot{
			Requests2xx: c.HTTP.Requests2xx.Load(),
			Requests4xx: c.HTTP.Requests4xx.Load(),
			Requests429: c.HTTP.Requests429.Load(),
			Requests5xx: c.HTTP.Requests5xx.Load(),
		},
		RateLimit: RateLimitSnapshot{
			RejectedGlobal:    c.RateLimit.RejectedGlobal.Load(),
			RejectedPerIP:     c.RateLimit.RejectedPerIP.Load(),
			RejectedPerDevice: c.RateLimit.RejectedPerDevice.Load(),
		},
		Enrollment: EnrollSnapshot{
			Phase1Started:          c.Enroll.Phase1Started.Load(),
			Phase1CapacityExceeded: c.Enroll.Phase1CapacityExceeded.Load(),
			Phase2Completed:        c.Enroll.Phase2Completed.Load(),
			Phase2Failed:           c.Enroll.Phase2Failed.Load(),
			Reenrolled:             c.Enroll.Reenrolled.Load(),
		},
		DNS: DNSSnapshot{
			UDPQueries: c.DNS.UDPQueries.Load(),
			TCPQueries: c.DNS.TCPQueries.Load(),
			UDPDropped: c.DNS.UDPDropped.Load(),
			TCPDropped: c.DNS.TCPDropped.Load(),
			Errors:     c.DNS.Errors.Load(),
		},
		ACME: ACMESnapshot{
			ChallengesCreated: c.ACME.ChallengesCreated.Load(),
			ChallengesDeleted: c.ACME.ChallengesDeleted.Load(),
			ChallengesExpired: c.ACME.ChallengesExpired.Load(),
			DNSSetFailed:      c.ACME.DNSSetFailed.Load(),
			VerifyOK:          c.ACME.VerifyOK.Load(),
			VerifyFailed:      c.ACME.VerifyFailed.Load(),
		},
		LastSeen: LastSeenSnapshot{
			FlushSuccess:   c.LastSeen.FlushSuccess.Load(),
			FlushErrors:    c.LastSeen.FlushErrors.Load(),
			EntriesDropped: c.LastSeen.EntriesDropped.Load(),
		},
		Census: CensusSnapshot{
			RunsCompleted:   c.Census.RunsCompleted.Load(),
			RunsFailed:      c.Census.RunsFailed.Load(),
			LastCompletedAt: c.Census.LastCompletedAt.Load(),
			LastDurationMs:  c.Census.LastDurationMs.Load(),
		},
		Nexus: NexusSnapshot{
			Registered:     c.Nexus.Registered.Load(),
			Reactivated:    c.Nexus.Reactivated.Load(),
			MarkedInactive: c.Nexus.MarkedInactive.Load(),
		},
		Recovery: RecoverySnapshot{
			ClaimsSubmitted:   c.Recovery.ClaimsSubmitted.Load(),
			QuorumReached:     c.Recovery.QuorumReached.Load(),
			AccountsDissolved: c.Recovery.AccountsDissolved.Load(),
		},
		Nonce: NonceSnapshot{
			CapacityRejected: c.Nonce.CapacityRejected.Load(),
			ConsumeNotFound:  c.Nonce.ConsumeNotFound.Load(),
		},
	}
}

// Snapshot types — JSON-serializable copies of counter values.

type Snapshot struct {
	HTTP       HTTPSnapshot      `json:"http"`
	RateLimit  RateLimitSnapshot `json:"rate_limit"`
	Enrollment EnrollSnapshot    `json:"enrollment"`
	DNS        DNSSnapshot       `json:"dns"`
	ACME       ACMESnapshot      `json:"acme"`
	LastSeen   LastSeenSnapshot  `json:"last_seen"`
	Census     CensusSnapshot    `json:"census"`
	Nexus      NexusSnapshot     `json:"nexus"`
	Recovery   RecoverySnapshot  `json:"recovery"`
	Nonce      NonceSnapshot     `json:"nonce"`
}

type HTTPSnapshot struct {
	Requests2xx int64 `json:"requests_2xx"`
	Requests4xx int64 `json:"requests_4xx"`
	Requests429 int64 `json:"requests_429"`
	Requests5xx int64 `json:"requests_5xx"`
}

type RateLimitSnapshot struct {
	RejectedGlobal    int64 `json:"rejected_global"`
	RejectedPerIP     int64 `json:"rejected_per_ip"`
	RejectedPerDevice int64 `json:"rejected_per_device"`
}

type EnrollSnapshot struct {
	Phase1Started          int64 `json:"phase1_started"`
	Phase1CapacityExceeded int64 `json:"phase1_capacity_exceeded"`
	Phase2Completed        int64 `json:"phase2_completed"`
	Phase2Failed           int64 `json:"phase2_failed"`
	Reenrolled             int64 `json:"reenrolled"`
}

type DNSSnapshot struct {
	UDPQueries int64 `json:"udp_queries"`
	TCPQueries int64 `json:"tcp_queries"`
	UDPDropped int64 `json:"udp_dropped"`
	TCPDropped int64 `json:"tcp_dropped"`
	Errors     int64 `json:"errors"`
}

type ACMESnapshot struct {
	ChallengesCreated int64 `json:"challenges_created"`
	ChallengesDeleted int64 `json:"challenges_deleted"`
	ChallengesExpired int64 `json:"challenges_expired"`
	DNSSetFailed      int64 `json:"dns_set_failed"`
	VerifyOK          int64 `json:"verify_ok"`
	VerifyFailed      int64 `json:"verify_failed"`
}

type LastSeenSnapshot struct {
	FlushSuccess   int64 `json:"flush_success"`
	FlushErrors    int64 `json:"flush_errors"`
	EntriesDropped int64 `json:"entries_dropped"`
}

type CensusSnapshot struct {
	RunsCompleted   int64 `json:"runs_completed"`
	RunsFailed      int64 `json:"runs_failed"`
	LastCompletedAt int64 `json:"last_completed_unix"`
	LastDurationMs  int64 `json:"last_duration_ms"`
}

type NexusSnapshot struct {
	Registered     int64 `json:"registered"`
	Reactivated    int64 `json:"reactivated"`
	MarkedInactive int64 `json:"marked_inactive"`
}

type RecoverySnapshot struct {
	ClaimsSubmitted   int64 `json:"claims_submitted"`
	QuorumReached     int64 `json:"quorum_reached"`
	AccountsDissolved int64 `json:"accounts_dissolved"`
}

type NonceSnapshot struct {
	CapacityRejected int64 `json:"capacity_rejected"`
	ConsumeNotFound  int64 `json:"consume_not_found"`
}
