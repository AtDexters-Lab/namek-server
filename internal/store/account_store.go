package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/AtDexters-Lab/namek-server/internal/model"
)

var ErrAccountNotFound = errors.New("account not found")

type AccountStore struct {
	pool *pgxpool.Pool
}

func NewAccountStore(pool *pgxpool.Pool) *AccountStore {
	return &AccountStore{pool: pool}
}

func (s *AccountStore) Create(ctx context.Context, account *model.Account) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO accounts (id) VALUES ($1)
	`, account.ID)
	if err != nil {
		return fmt.Errorf("insert account: %w", err)
	}
	return nil
}

func (s *AccountStore) GetByID(ctx context.Context, id uuid.UUID) (*model.Account, error) {
	a := &model.Account{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, created_at FROM accounts WHERE id = $1
	`, id).Scan(&a.ID, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAccountNotFound
		}
		return nil, fmt.Errorf("get account by id: %w", err)
	}
	return a, nil
}
