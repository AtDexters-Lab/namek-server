package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Stores struct {
	Device   *DeviceStore
	Nexus    *NexusStore
	ACME     *ACMEStore
	Audit    *AuditStore
	Account  *AccountStore
	Domain   *DomainStore
	Invite   *InviteStore
	Voucher  *VoucherStore
	Recovery *RecoveryStore
	Census   *CensusStore
}

// countGroupBy runs "SELECT column, COUNT(*) FROM table GROUP BY column" and
// scans the result into map[string]int. column and table are always hardcoded
// by callers, never user input.
func countGroupBy(ctx context.Context, pool *pgxpool.Pool, table, column string) (map[string]int, error) {
	rows, err := pool.Query(ctx, "SELECT "+column+", COUNT(*) FROM "+table+" GROUP BY "+column)
	if err != nil {
		return nil, fmt.Errorf("count %s by %s: %w", table, column, err)
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return nil, fmt.Errorf("scan %s count: %w", table, err)
		}
		result[key] = count
	}
	return result, rows.Err()
}

func New(pool *pgxpool.Pool) *Stores {
	return &Stores{
		Device:   NewDeviceStore(pool),
		Nexus:    NewNexusStore(pool),
		ACME:     NewACMEStore(pool),
		Audit:    NewAuditStore(pool),
		Account:  NewAccountStore(pool),
		Domain:   NewDomainStore(pool),
		Invite:   NewInviteStore(pool),
		Voucher:  NewVoucherStore(pool),
		Recovery: NewRecoveryStore(pool),
		Census:   NewCensusStore(pool),
	}
}
