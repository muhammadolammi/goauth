package goauth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID
	PasswordHash string
}
type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Token      string
	Revoked    bool
	ReplacedBy uuid.NullUUID
	ExpiresAt  time.Time
	CreatedAt  time.Time
}
type CreateRefreshTokenParams struct {
	UserID    uuid.UUID
	ExpiresAt time.Time
	Token     string
}

type UpdateRefreshTokenParams struct {
	ID         uuid.UUID
	Revoked    bool
	ReplacedBy uuid.NullUUID
}

type IdentityProvider interface {
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	CreateRefreshToken(ctx context.Context, arg *CreateRefreshTokenParams) (*RefreshToken, error)
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, arg *UpdateRefreshTokenParams) error
	RevokeUserTokens(ctx context.Context, userID uuid.UUID) error // For security breaches
}
