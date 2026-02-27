package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

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
