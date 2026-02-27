package store

import "github.com/jackc/pgx/v5/pgxpool"

type Stores struct {
	Device *DeviceStore
	Nexus  *NexusStore
	ACME   *ACMEStore
	Audit  *AuditStore
}

func New(pool *pgxpool.Pool) *Stores {
	return &Stores{
		Device: NewDeviceStore(pool),
		Nexus:  NewNexusStore(pool),
		ACME:   NewACMEStore(pool),
		Audit:  NewAuditStore(pool),
	}
}
