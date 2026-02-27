package model

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type NexusStatus string

const (
	NexusStatusActive   NexusStatus = "active"
	NexusStatusInactive NexusStatus = "inactive"
)

type NexusInstance struct {
	ID                       uuid.UUID   `json:"id"`
	Hostname                 string      `json:"hostname"`
	ResolvedAddresses        []net.IP    `json:"resolved_addresses"`
	Region                   *string     `json:"region,omitempty"`
	HeartbeatIntervalSeconds int         `json:"heartbeat_interval_seconds"`
	Status                   NexusStatus `json:"status"`
	RegisteredAt             time.Time   `json:"registered_at"`
	LastSeenAt               time.Time   `json:"last_seen_at"`
}
