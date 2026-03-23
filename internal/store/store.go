package store

import "github.com/jackc/pgx/v5/pgxpool"

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
	}
}
