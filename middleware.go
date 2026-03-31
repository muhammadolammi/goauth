package goauth

import (
	"context"
	"net/http"
	"strings"
)

func (s *AuthService) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Get token from Header (Authorization: Bearer <token>)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			RespondWithError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			RespondWithError(w, http.StatusUnauthorized, "invalid authorization format")
			return
		}
		// 2. Validate using your existing ValidateToken logic
		claims, err := ValidateToken(bearerToken[1], s.JwtSecret)
		if err != nil {
			RespondWithError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		// 3. Check Fingerprint cookie
		fgpName := "__Secure-Fgp"
		if !s.IsProduction {
			// log.Println("not secured env")
			fgpName = "session_fgp"

		}
		fpCookie, err := r.Cookie(fgpName)
		if err != nil {
			RespondWithError(w, http.StatusUnauthorized, "missing security fingerprint")
			return
		}
		if claims.Fingerprint != HashFingerprint(fpCookie.Value) {
			RespondWithError(w, 401, "Invalid Session")
			return
		}
		// 4. If valid, add UserID to context and call next.ServeHTTP
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
