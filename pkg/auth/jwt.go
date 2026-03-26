package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// GenerateFingerprint creates a random 32-byte string
func GenerateFingerprint() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashFingerprint returns the SHA-256 hash of the fingerprint
// This goes INTO the JWT claims
func HashFingerprint(f string) string {
	hash := sha256.Sum256([]byte(f))
	return hex.EncodeToString(hash[:])
}

type Claims struct {
	UserID      string `json:"user_id"`
	Fingerprint string `json:"fgp"` // Hash of the fingerprint
	jwt.RegisteredClaims
}

func MakeJwtTokenString(s *AuthService, userId, fingerprint string, tokenExpiration time.Duration) (string, error) {
	hashedFingerprint := HashFingerprint(fingerprint)
	claims := Claims{
		UserID:      userId,
		Fingerprint: hashedFingerprint,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(tokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.JwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

func CreateRefreshToken(s *AuthService, userId uuid.UUID, fingerprint string, w http.ResponseWriter) (*RefreshToken, error) {
	// create new jwt refresh token
	jwtRefreshTokenString, err := MakeJwtTokenString(s, userId.String(), fingerprint, s.RefreshExpiry)
	if err != nil {
		return &RefreshToken{}, err
	}
	expiresAt := time.Now().UTC().Add(time.Duration(s.RefreshExpiry) * time.Minute)
	sameSite := http.SameSiteStrictMode
	if s.IsProduction {
		sameSite = http.SameSiteNoneMode
	}
	//  save to http cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    jwtRefreshTokenString,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.IsProduction,
		SameSite: sameSite,
	})
	fgpName := "__Secure-Fgp"
	if !s.IsProduction {
		fgpName = "session_fgp"

	}
	http.SetCookie(w, &http.Cookie{
		Name:     fgpName,
		Value:    fingerprint,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.IsProduction,
		SameSite: sameSite,
	})
	// save refresh to db
	refreshToken, err := s.Provider.CreateRefreshToken(context.Background(), &CreateRefreshTokenParams{
		ExpiresAt: expiresAt,
		Token:     jwtRefreshTokenString,
		UserID:    userId,
	})

	if err != nil {
		return &RefreshToken{}, err
	}

	return refreshToken, nil
}

// ValidateToken should be strict about the algorithm
func ValidateToken(tokenString string, jwtSecret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Critical: Validate the algorithm to prevent "none" or "HMAC vs RSA" attacks
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("could not parse claims")
	}
	return claims, nil
}

func (s *AuthService) ClearAuthCookies(w http.ResponseWriter) {
	// We set the MaxAge to -1 and Expires to a date in the past
	expired := time.Unix(0, 0)
	sameSite := http.SameSiteStrictMode
	if s.IsProduction {
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  expired,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.IsProduction,
		SameSite: sameSite,
	})
	fgpName := "__Secure-Fgp"
	if !s.IsProduction {
		fgpName = "session_fgp"

	}
	http.SetCookie(w, &http.Cookie{
		Name:     fgpName,
		Value:    "",
		Path:     "/",
		Expires:  expired,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.IsProduction,
		SameSite: sameSite,
	})

}
