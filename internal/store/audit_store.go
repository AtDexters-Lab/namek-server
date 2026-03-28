package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

// AuditQuery specifies filters for querying the audit log.
type AuditQuery struct {
	Action       *string    // prefix filter (e.g. "device." matches device.enrolled, etc.)
	ActorType    *string    // exact match
	ResourceType *string    // exact match
	Since        *time.Time // entries after this time
	Until        *time.Time // entries before this time
	Limit        int        // max results (default 50, max 200)
	Before       *int64     // cursor: return entries with id < Before
}

type AuditStore struct {
	pool *pgxpool.Pool
}

func NewAuditStore(pool *pgxpool.Pool) *AuditStore {
	return &AuditStore{pool: pool}
}

func (s *AuditStore) Log(ctx context.Context, entry *model.AuditEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor_type, actor_id, action, resource_type, resource_id, details, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, entry.ActorType, entry.ActorID, entry.Action, entry.ResourceType,
		entry.ResourceID, entry.Details, ipToString(entry.IPAddress))
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

func (s *AuditStore) LogAction(ctx context.Context, actorType model.ActorType, actorID, action, resourceType string, resourceID *string, details any, ip net.IP) {
	var detailsJSON json.RawMessage
	if details != nil {
		b, err := json.Marshal(details)
		if err == nil {
			detailsJSON = b
		}
	}
	// Best-effort audit logging — don't fail the request
	_ = s.Log(ctx, &model.AuditEntry{
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      detailsJSON,
		IPAddress:    ip,
	})
}

// Query returns audit log entries matching the given filters, ordered newest-first.
// Uses cursor-based pagination via Before (id < cursor). All filter values are parameterized.
// Callers must clamp q.Limit before calling; a zero or negative limit defaults to 50.
func (s *AuditStore) Query(ctx context.Context, q AuditQuery) ([]model.AuditEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}

	query := "SELECT id, timestamp, actor_type, actor_id, action, resource_type, resource_id, details, host(ip_address) FROM audit_log"
	var conditions []string
	var args []any
	argN := 1

	if q.Before != nil {
		conditions = append(conditions, fmt.Sprintf("id < $%d", argN))
		args = append(args, *q.Before)
		argN++
	}
	if q.Action != nil {
		conditions = append(conditions, fmt.Sprintf("starts_with(action, $%d)", argN))
		args = append(args, *q.Action)
		argN++
	}
	if q.ActorType != nil {
		conditions = append(conditions, fmt.Sprintf("actor_type = $%d", argN))
		args = append(args, *q.ActorType)
		argN++
	}
	if q.ResourceType != nil {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argN))
		args = append(args, *q.ResourceType)
		argN++
	}
	if q.Since != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argN))
		args = append(args, *q.Since)
		argN++
	}
	if q.Until != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argN))
		args = append(args, *q.Until)
		argN++
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += cond
		}
	}

	query += fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", argN)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	var entries []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var ipStr *string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ActorType, &e.ActorID, &e.Action,
			&e.ResourceType, &e.ResourceID, &e.Details, &ipStr); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if ipStr != nil {
			e.IPAddress = net.ParseIP(*ipStr)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *AuditStore) DeleteOlderThan(ctx context.Context, days int) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM audit_log
		WHERE id IN (
			SELECT id FROM audit_log
			WHERE timestamp < NOW() - make_interval(days => $1)
			LIMIT 1000
		)
	`, days)
	if err != nil {
		return 0, fmt.Errorf("delete old audit logs: %w", err)
	}
	return tag.RowsAffected(), nil
}
