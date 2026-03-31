package goauth

import (
	"time"
)

type AuthService struct {
	Issuer        string
	JwtSecret     []byte
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	Provider      IdentityProvider // The injected DB
	IsProduction  bool
}

func NewAuthService(secret, issuerName string, provider IdentityProvider, isProd bool) *AuthService {
	return &AuthService{
		Issuer:        issuerName,
		JwtSecret:     []byte(secret),
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
		Provider:      provider,
		IsProduction:  isProd,
	}
}
