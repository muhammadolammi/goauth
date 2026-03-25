package auth

import (
	"database/sql"
	"time"
)

type AuthService struct {
	Issuer        string
	JwtSecret     []byte
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	Provider      IdentityProvider // The injected DB
	IsProduction  bool
	RefreshDbConn *sql.DB
}

func NewAuthService(secret, issuerName string, provider IdentityProvider, isProd bool, refreshDbConn *sql.DB) *AuthService {
	return &AuthService{
		Issuer:        issuerName,
		JwtSecret:     []byte(secret),
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
		Provider:      provider,
		IsProduction:  isProd,
		RefreshDbConn: refreshDbConn,
	}
}
