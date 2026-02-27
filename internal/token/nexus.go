package token

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/AtDexters-Lab/namek-server/internal/config"
)

type UDPRouteClaim struct {
	Port                   int  `json:"port"`
	FlowIdleTimeoutSeconds *int `json:"flow_idle_timeout_seconds"`
}

type NexusClaims struct {
	Hostnames                  []string        `json:"hostnames"`
	TCPPorts                   []int           `json:"tcp_ports"`
	UDPRoutes                  []UDPRouteClaim `json:"udp_routes"`
	Weight                     int             `json:"weight"`
	SessionNonce               string          `json:"session_nonce"`
	HandshakeMaxAgeSeconds     *int            `json:"handshake_max_age_seconds"`
	ReauthIntervalSeconds      *int            `json:"reauth_interval_seconds"`
	ReauthGraceSeconds         *int            `json:"reauth_grace_seconds"`
	MaintenanceGraceCapSeconds *int            `json:"maintenance_grace_cap_seconds"`
	AuthorizerStatusURI        string          `json:"authorizer_status_uri"`
	PolicyVersion              string          `json:"policy_version"`
	IssuedAtQuote              string          `json:"issued_at_quote"`
	jwt.RegisteredClaims
}

type Issuer struct {
	secret         []byte
	ttl            time.Duration
	publicHostname string
	tokenCfg       config.TokenConfig
	logger         *slog.Logger
}

func NewIssuer(cfg config.TokenConfig, publicHostname string, logger *slog.Logger) (*Issuer, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate signing secret: %w", err)
	}

	logger.Info("generated ephemeral JWT signing secret (will invalidate on restart)")

	return &Issuer{
		secret:         secret,
		ttl:            time.Duration(cfg.TTLSeconds) * time.Second,
		publicHostname: publicHostname,
		tokenCfg:       cfg,
		logger:         logger,
	}, nil
}

type IssueParams struct {
	DeviceID     string
	Hostnames    []string
	Stage        int
	SessionNonce string
}

func (i *Issuer) Issue(params IssueParams) (string, error) {
	now := time.Now()

	handshakeMaxAge := i.tokenCfg.HandshakeMaxAgeSeconds
	reauthInterval := i.tokenCfg.ReauthIntervalSeconds
	reauthGrace := i.tokenCfg.ReauthGraceSeconds
	maintenanceGraceCap := i.tokenCfg.MaintenanceGraceCapSeconds

	claims := NexusClaims{
		Hostnames:                  params.Hostnames,
		TCPPorts:                   []int{},
		UDPRoutes:                  []UDPRouteClaim{},
		Weight:                     i.tokenCfg.DefaultWeight,
		SessionNonce:               params.SessionNonce,
		AuthorizerStatusURI:        fmt.Sprintf("https://%s/health", i.publicHostname),
		PolicyVersion:              "",
		IssuedAtQuote:              "",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "authorizer",
			Subject:   params.DeviceID,
			Audience:  jwt.ClaimStrings{"nexus"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}

	// Stage-specific fields
	switch params.Stage {
	case 0: // Handshake
		claims.HandshakeMaxAgeSeconds = &handshakeMaxAge
		claims.ReauthIntervalSeconds = &reauthInterval
		claims.ReauthGraceSeconds = &reauthGrace
		claims.MaintenanceGraceCapSeconds = &maintenanceGraceCap
		claims.SessionNonce = ""
	case 1: // Attest
		claims.ReauthIntervalSeconds = &reauthInterval
		claims.ReauthGraceSeconds = &reauthGrace
		claims.MaintenanceGraceCapSeconds = &maintenanceGraceCap
	case 2: // Reauth
		claims.ReauthIntervalSeconds = &reauthInterval
		claims.ReauthGraceSeconds = &reauthGrace
		claims.MaintenanceGraceCapSeconds = &maintenanceGraceCap
	default:
		return "", fmt.Errorf("invalid token stage: %d", params.Stage)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

func (i *Issuer) Verify(tokenString string) (*NexusClaims, error) {
	claims := &NexusClaims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithAudience("nexus"), jwt.WithIssuer("authorizer"))
	if err != nil {
		return nil, fmt.Errorf("jwt validation failed: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("invalid jwt token")
	}
	return claims, nil
}
