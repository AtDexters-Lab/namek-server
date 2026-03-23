package model

import (
	"encoding/json"
	"net"
	"time"
)

type ActorType string

const (
	ActorTypeDevice   ActorType = "device"
	ActorTypeNexus    ActorType = "nexus"
	ActorTypeSystem   ActorType = "system"
	ActorTypeOperator ActorType = "operator"
)

type AuditEntry struct {
	ID           int64           `json:"id"`
	Timestamp    time.Time       `json:"timestamp"`
	ActorType    ActorType       `json:"actor_type"`
	ActorID      string          `json:"actor_id"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	IPAddress    net.IP          `json:"ip_address,omitempty"`
}
