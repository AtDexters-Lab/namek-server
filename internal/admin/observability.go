package admin

import (
	"context"
	"log/slog"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/auth"
	"github.com/AtDexters-Lab/namek-server/internal/httputil"
	"github.com/AtDexters-Lab/namek-server/internal/metrics"
	"github.com/AtDexters-Lab/namek-server/internal/store"
)

// PendingCounter exposes the pending enrollment count from DeviceService.
type PendingCounter interface {
	PendingCount() int
}

type fleetResult struct {
	data     gin.H
	cachedAt time.Time
}

// ObservabilityHandler serves system health, metrics, fleet summary, and audit log.
type ObservabilityHandler struct {
	pool           *pgxpool.Pool
	nonceStore     *auth.NonceStore
	auditStore     *store.AuditStore
	deviceStore    *store.DeviceStore
	accountStore   *store.AccountStore
	nexusStore     *store.NexusStore
	censusStore    *store.CensusStore
	pendingCounter PendingCounter
	logger         *slog.Logger

	censusAnalysisInterval time.Duration
	maxPendingEnrollments  int

	fleetMu    sync.Mutex
	fleetCache *fleetResult
}

func newObservabilityHandler(deps *OperatorDeps, logger *slog.Logger) *ObservabilityHandler {
	return &ObservabilityHandler{
		pool:                   deps.Pool,
		nonceStore:             deps.NonceStore,
		auditStore:             deps.AuditStore,
		deviceStore:            deps.DeviceStore,
		accountStore:           deps.AccountStore,
		nexusStore:             deps.NexusStore,
		censusStore:            deps.CensusStore,
		pendingCounter:         deps.PendingCounter,
		censusAnalysisInterval: deps.CensusAnalysisInterval,
		maxPendingEnrollments:  deps.MaxPendingEnrollments,
		logger:                 logger,
	}
}

// SystemHealth returns system health snapshot with alerts. No DB queries.
func (h *ObservabilityHandler) SystemHealth(c *gin.Context) {
	m := metrics.Get()
	snap := m.Snapshot()
	now := time.Now()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	poolStat := h.pool.Stat()

	var acquireAvgMs float64
	if poolStat.AcquireCount() > 0 {
		acquireAvgMs = float64(poolStat.AcquireDuration().Microseconds()) / float64(poolStat.AcquireCount()) / 1000.0
	}

	nonceCount := h.nonceStore.Count()
	nonceMax := h.nonceStore.MaxNonces()
	var nonceUtilPct float64
	if nonceMax > 0 {
		nonceUtilPct = float64(nonceCount) / float64(nonceMax) * 100.0
	}

	pendingEnrollments := 0
	if h.pendingCounter != nil {
		pendingEnrollments = h.pendingCounter.PendingCount()
	}

	type alert struct {
		Severity  string `json:"severity"`
		Component string `json:"component"`
		Message   string `json:"message"`
		Action    string `json:"action"`
		Value     int64  `json:"value"`
	}
	var alerts []alert

	if nonceUtilPct > 90 {
		alerts = append(alerts, alert{"warning", "nonce_store", "Nonce store utilization above 90%", "Increase nonce.maxNonces in config", nonceCount})
	}
	// Alert on flush error rate, not lifetime count — avoids permanent alert from one transient failure
	if snap.LastSeen.FlushErrors > 0 && (snap.LastSeen.FlushSuccess == 0 || snap.LastSeen.FlushErrors*10 > snap.LastSeen.FlushSuccess) {
		alerts = append(alerts, alert{"warning", "last_seen", "High last-seen flush error rate", "Check database connectivity — device IP updates are being dropped", snap.LastSeen.FlushErrors})
	}
	uptime := now.Sub(m.StartedAt)
	if h.censusAnalysisInterval > 0 {
		if snap.Census.LastCompletedAt > 0 {
			lastCensus := time.Unix(snap.Census.LastCompletedAt, 0)
			if now.Sub(lastCensus) > 2*h.censusAnalysisInterval {
				alerts = append(alerts, alert{"warning", "census", "Census analysis overdue", "Check database connectivity", int64(now.Sub(lastCensus).Seconds())})
			}
		} else if uptime > 2*h.censusAnalysisInterval {
			// Census enabled but has never completed successfully since startup
			alerts = append(alerts, alert{"warning", "census", "Census has never completed successfully", "Check database connectivity and census configuration", snap.Census.RunsFailed})
		}
	}
	if poolStat.AcquiredConns() >= poolStat.MaxConns() {
		alerts = append(alerts, alert{"warning", "db_pool", "Database connection pool exhausted", "Increase pool size or investigate slow queries", int64(poolStat.AcquiredConns())})
	}
	if runtime.NumGoroutine() > 1000 {
		alerts = append(alerts, alert{"warning", "runtime", "High goroutine count", "Possible goroutine leak — investigate", int64(runtime.NumGoroutine())})
	}
	if h.maxPendingEnrollments > 0 && float64(pendingEnrollments) > 0.8*float64(h.maxPendingEnrollments) {
		alerts = append(alerts, alert{"warning", "enrollment", "Enrollment queue near capacity", "Pending enrollments approaching maxPending limit", int64(pendingEnrollments)})
	}

	httputil.RespondOK(c, gin.H{
		"snapshot_at":    now,
		"uptime_seconds": int64(now.Sub(m.StartedAt).Seconds()),
		"go": gin.H{
			"goroutines":    runtime.NumGoroutine(),
			"heap_alloc_mb": float64(memStats.HeapAlloc) / 1024 / 1024,
			"sys_mb":        float64(memStats.Sys) / 1024 / 1024,
			"gc_pause_ms":   float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6,
		},
		"db_pool": gin.H{
			"acquired":                poolStat.AcquiredConns(),
			"idle":                    poolStat.IdleConns(),
			"max":                     poolStat.MaxConns(),
			"total_acquires":          poolStat.AcquireCount(),
			"acquire_duration_avg_ms": acquireAvgMs,
		},
		"nonce_store": gin.H{
			"count":           nonceCount,
			"max":             nonceMax,
			"utilization_pct": nonceUtilPct,
		},
		"pending_enrollments": pendingEnrollments,
		"alerts":              alerts,
	})
}

// Metrics returns the raw metrics snapshot.
func (h *ObservabilityHandler) Metrics(c *gin.Context) {
	httputil.RespondOK(c, metrics.Get().Snapshot())
}

// FleetSummary returns aggregate fleet stats, cached for 30 seconds.
func (h *ObservabilityHandler) FleetSummary(c *gin.Context) {
	const cacheTTL = 30 * time.Second

	// Check cache under lock; return immediately if fresh
	h.fleetMu.Lock()
	if h.fleetCache != nil && time.Since(h.fleetCache.cachedAt) < cacheTTL {
		cached := h.fleetCache.data
		h.fleetMu.Unlock()
		httputil.RespondOK(c, cached)
		return
	}
	// Hold the lock through the fetch to prevent thundering herd.
	// Admin endpoint with low concurrency — blocking is acceptable.
	defer h.fleetMu.Unlock()

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	byStatus, err := h.deviceStore.CountByStatus(ctx)
	if err != nil {
		h.logger.Error("fleet summary: devices by status", "error", err)
		httputil.RespondInternalError(c)
		return
	}
	byTrust, err := h.deviceStore.CountByTrustLevel(ctx)
	if err != nil {
		h.logger.Error("fleet summary: devices by trust", "error", err)
		httputil.RespondInternalError(c)
		return
	}
	byClass, err := h.deviceStore.CountByIdentityClass(ctx)
	if err != nil {
		h.logger.Error("fleet summary: devices by class", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	var deviceTotal int
	for _, v := range byStatus {
		deviceTotal += v
	}

	accountStatus, err := h.accountStore.CountByStatus(ctx)
	if err != nil {
		h.logger.Error("fleet summary: accounts by status", "error", err)
		httputil.RespondInternalError(c)
		return
	}
	var accountTotal int
	for _, v := range accountStatus {
		accountTotal += v
	}

	nexusStatus, err := h.nexusStore.CountByStatus(ctx)
	if err != nil {
		h.logger.Error("fleet summary: nexus by status", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	issuerSummary, err := h.censusStore.GetIssuerSummary(ctx)
	if err != nil {
		h.logger.Error("fleet summary: issuer summary", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	now := time.Now()
	result := gin.H{
		"cached_at": now,
		"devices": gin.H{
			"total":             deviceTotal,
			"by_status":         byStatus,
			"by_trust_level":    byTrust,
			"by_identity_class": byClass,
		},
		"accounts": gin.H{
			"total":            accountTotal,
			"pending_recovery": accountStatus["pending_recovery"],
		},
		"nexus": gin.H{
			"active":   nexusStatus["active"],
			"inactive": nexusStatus["inactive"],
		},
		"issuers": gin.H{
			"total":   issuerSummary.Total,
			"by_tier": issuerSummary.ByTier,
			"flagged": issuerSummary.Flagged,
		},
	}

	h.fleetCache = &fleetResult{data: result, cachedAt: now}
	httputil.RespondOK(c, result)
}

// AuditLog returns paginated audit entries with filters.
func (h *ObservabilityHandler) AuditLog(c *gin.Context) {
	q := store.AuditQuery{}

	if v := c.Query("action"); v != "" {
		q.Action = &v
	}
	if v := c.Query("actor_type"); v != "" {
		q.ActorType = &v
	}
	if v := c.Query("resource_type"); v != "" {
		q.ResourceType = &v
	}
	if v := c.Query("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Since = &t
		}
	}
	if v := c.Query("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			q.Until = &t
		}
	}
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			q.Limit = n
		}
	}
	if v := c.Query("before"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			q.Before = &n
		}
	}

	// Clamp limit here; Query() trusts the input after clamping.
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 200 {
		q.Limit = 200
	}

	// Fetch one extra row to determine has_more without a false positive on exact page boundaries.
	requestedLimit := q.Limit
	q.Limit = requestedLimit + 1

	entries, err := h.auditStore.Query(c.Request.Context(), q)
	if err != nil {
		h.logger.Error("audit query failed", "error", err)
		httputil.RespondInternalError(c)
		return
	}

	hasMore := len(entries) > requestedLimit
	if hasMore {
		entries = entries[:requestedLimit]
	}

	httputil.RespondOK(c, gin.H{
		"entries":  entries,
		"has_more": hasMore,
	})
}
