package goauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func (s *AuthService) GetUserIdFromRequest(r *http.Request) (uuid.UUID, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return uuid.Nil, errors.New("missing authorization header")
	}

	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
		return uuid.Nil, errors.New("invalid authorization format")

	}
	// 2. Validate using your existing ValidateToken logic
	claims, err := ValidateToken(bearerToken[1], s.JwtSecret)
	if err != nil {
		return uuid.Nil, errors.New("invalid token")

	}
	// 3. Check Fingerprint cookie

	fgpName := "session_fgp"
	if s.IsProduction {
		// log.Println("not secured env")
		fgpName = "__Secure-Fgp"

	}
	fpCookie, err := r.Cookie(fgpName)
	if err != nil {
		return uuid.Nil, errors.New("missing security fingerprint")

	}
	if claims.Fingerprint != HashFingerprint(fpCookie.Value) {
		return uuid.Nil, errors.New("Invalid Session")
	}

	parsedID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return uuid.Nil, errors.New("error parsing user id")
	}
	return parsedID, nil

}
