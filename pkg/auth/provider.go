package auth

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

type IdentityProvider interface {
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
	CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error)
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	SaveRefreshToken(ctx context.Context, rt *RefreshToken) error
	UpdateRefreshToken(ctx context.Context, rt *RefreshToken) error
	RevokeUserTokens(ctx context.Context, userID uuid.UUID) error // For security breaches
}
