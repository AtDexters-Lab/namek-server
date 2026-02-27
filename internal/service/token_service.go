package service

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/AtDexters-Lab/namek-server/internal/config"
	"github.com/AtDexters-Lab/namek-server/internal/model"
	"github.com/AtDexters-Lab/namek-server/internal/store"
	"github.com/AtDexters-Lab/namek-server/internal/token"
)

type TokenService struct {
	deviceStore *store.DeviceStore
	issuer      *token.Issuer
	cfg         *config.Config
	logger      *slog.Logger
}

func NewTokenService(deviceStore *store.DeviceStore, issuer *token.Issuer, cfg *config.Config, logger *slog.Logger) *TokenService {
	return &TokenService{
		deviceStore: deviceStore,
		issuer:      issuer,
		cfg:         cfg,
		logger:      logger,
	}
}

type IssueTokenRequest struct {
	DeviceID     uuid.UUID
	Stage        int
	SessionNonce string
}

func (s *TokenService) IssueNexusToken(ctx context.Context, req IssueTokenRequest) (string, error) {
	device, err := s.deviceStore.GetByID(ctx, req.DeviceID)
	if err != nil {
		return "", fmt.Errorf("get device: %w", err)
	}

	if device.Status != model.DeviceStatusActive {
		return "", fmt.Errorf("device is %s", device.Status)
	}

	// Build hostnames list
	hostnames := []string{device.Hostname}
	if device.CustomHostname != nil {
		hostnames = append(hostnames, fmt.Sprintf("%s.%s", *device.CustomHostname, s.cfg.DNS.BaseDomain))
	}

	tokenStr, err := s.issuer.Issue(token.IssueParams{
		DeviceID:     device.ID.String(),
		Hostnames:    hostnames,
		Stage:        req.Stage,
		SessionNonce: req.SessionNonce,
	})
	if err != nil {
		return "", fmt.Errorf("issue token: %w", err)
	}

	return tokenStr, nil
}

type VerifyResult struct {
	Valid  bool              `json:"valid"`
	Claims *token.NexusClaims `json:"claims"`
	Error  string            `json:"error"`
}

func (s *TokenService) VerifyToken(tokenString string) *VerifyResult {
	claims, err := s.issuer.Verify(tokenString)
	if err != nil {
		return &VerifyResult{
			Valid:  false,
			Claims: nil,
			Error:  err.Error(),
		}
	}
	return &VerifyResult{
		Valid:  true,
		Claims: claims,
		Error:  "",
	}
}
