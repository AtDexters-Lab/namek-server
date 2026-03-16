package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/acme/autocert"
)

// PGCertStore implements autocert.Cache backed by Postgres.
type PGCertStore struct {
	pool *pgxpool.Pool
}

func NewPGCertStore(pool *pgxpool.Pool) *PGCertStore {
	return &PGCertStore{pool: pool}
}

func (s *PGCertStore) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	err := s.pool.QueryRow(ctx, "SELECT data FROM acme_certs WHERE key = $1", key).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("acme cache get %q: %w", key, err)
	}
	return data, nil
}

func (s *PGCertStore) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO acme_certs (key, data) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
		key, data,
	)
	if err != nil {
		return fmt.Errorf("acme cache put %q: %w", key, err)
	}
	return nil
}

func (s *PGCertStore) Delete(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM acme_certs WHERE key = $1", key)
	if err != nil {
		return fmt.Errorf("acme cache delete %q: %w", key, err)
	}
	return nil
}
