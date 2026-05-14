package goauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (s *AuthService) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Parse JSON (email, password)
	body := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&body)

	if err != nil {
		RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("error decoding body from http request. err: %v", err))
		return
	}
	if body.Email == "" {
		RespondWithError(w, http.StatusBadRequest, "enter a mail")
		return
	}
	if body.Password == "" {
		RespondWithError(w, http.StatusBadRequest, "enter a password")
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	// 2. user, err := s.Provider.GetByEmail(ctx, email)
	user, err := s.Provider.GetByEmail(r.Context(), body.Email)
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "invalid user")
		return
	}
	// 3. Compare passwords
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password))
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "invalid user")
		return
	}

	// 4. Generate Fingerprint & Tokens
	fingerprint, err := GenerateFingerprint()
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error generating fingerprint")
		return
	}
	accessToken, err := MakeJwtTokenString(s, user.ID.String(), fingerprint, s.AccessExpiry)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error generating tokens")
		return
	}
	_, err = CreateRefreshToken(s, user.ID, fingerprint, w)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error generating tokens")
		return
	}
	res := struct {
		AccessToken string `json:"access_token"`
	}{
		AccessToken: accessToken,
	}
	RespondWithJson(w, http.StatusOK, res)
}
func (s *AuthService) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Get the Refresh Token from Cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "No refresh token")
		return
	}

	// 2. Get the Fingerprint from the Secure Cookie
	fgpName := "__Secure-Fgp"
	if !s.IsProduction {
		fgpName = "session_fgp"

	}
	fgpCookie, err := r.Cookie(fgpName)
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "Missing security fingerprint")
		return
	}

	// 3. Look up token in DB
	storedToken, err := s.Provider.GetRefreshToken(r.Context(), cookie.Value)
	if err != nil || time.Now().After(storedToken.ExpiresAt) {
		RespondWithError(w, http.StatusUnauthorized, "Token invalid or expired")
		return
	}
	if storedToken.Revoked {
		// This is a major red flag! Someone is trying to reuse a rotated token.
		// Potential breach detected.
		err = s.Provider.RevokeUserTokens(r.Context(), storedToken.UserID)
		if err != nil {
			RespondWithError(w, http.StatusUnauthorized, "error rotating tokens")
			return
		}
		s.ClearAuthCookies(w)
		log.Printf("Security breach detected. UserId: %v, time: %v \n", storedToken.UserID, time.Now())
		RespondWithError(w, http.StatusUnauthorized, "Security breach detected. Please login again.")
		return
	}
	// 4. Validate JWT & Fingerprint
	// Parse the JWT to get claims (UserID and the Hashed Fingerprint)
	claims, err := ValidateToken(cookie.Value, s.JwtSecret)
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "Invalid token signature")
		return
	}

	// CRITICAL: Compare the hash of the cookie fingerprint vs the hash in the JWT
	if HashFingerprint(fgpCookie.Value) != claims.Fingerprint {
		RespondWithError(w, http.StatusUnauthorized, "Fingerprint mismatch")
		return
	}

	// 5. Rotate: Create New Credentials
	newFingerprint, _ := GenerateFingerprint()
	newAccessToken, _ := MakeJwtTokenString(s, claims.UserID, newFingerprint, s.AccessExpiry)
	newRefreshToken, err := CreateRefreshToken(s, storedToken.UserID, newFingerprint, w)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "Rotation failed")
		return
	}
	// 6. Update DB: Mark old token as replaced by the new one

	arg := UpdateRefreshTokenParams{
		ID:      storedToken.ID,
		Revoked: true,
		ReplacedBy: uuid.NullUUID{
			Valid: true,
			UUID:  newRefreshToken.ID,
		},
	}
	// You would map the newRefreshTokenString to its ID here before saving
	s.Provider.UpdateRefreshToken(r.Context(), &arg)

	RespondWithJson(w, http.StatusOK, map[string]string{
		"access_token": newAccessToken,
	})
}

func (s *AuthService) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := r.Context().Value("user_id").(string)
	if !ok {
		RespondWithError(w, http.StatusUnauthorized, "User not found in context")
		return
	}
	parsedID, err := uuid.Parse(userIDStr)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error parsing user id")
	}
	user, err := s.Provider.GetByID(r.Context(), parsedID)
	if err != nil {
		RespondWithError(w, http.StatusUnauthorized, "error getting user")
	}
	s.Provider.RevokeUserTokens(r.Context(), user.ID)
	s.ClearAuthCookies(w)
	RespondWithJson(w, http.StatusOK, "")
}

type SignupInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
	Address     string `json:"address"`
	Country     string `json:"country"`
	State       string `json:"state"`
}

func validatePassword(password string) error {
	var (
		hasUpper  bool
		hasLower  bool
		hasSymbol bool
	)

	if len(password) < 10 {
		return fmt.Errorf("password must be at least 10 characters long")
	}

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if !hasUpper || !hasLower || !hasSymbol {
		return fmt.Errorf("password must include uppercase, lowercase, and a symbol")
	}

	return nil
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func (s *AuthService) SignupHandler(w http.ResponseWriter, r *http.Request) {
	var input SignupInput

	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "invalid request, err: "+err.Error())
		return
	}

	// Check if user already exists
	existingUser, _ := s.Provider.GetByEmail(context.Background(), input.Email)
	if existingUser.ID != uuid.Nil {
		RespondWithError(w, http.StatusConflict, "user with this email already exists")
		return
	}

	err = validatePassword(input.Password)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Hash password
	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Create user
	params := CreateUserParams{
		Email:        strings.ToLower(strings.TrimSpace(input.Email)),
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		PhoneNumber:  sql.NullString{String: input.PhoneNumber, Valid: input.PhoneNumber != ""},
		Address:      sql.NullString{Valid: true, String: input.Address},
		Country:      sql.NullString{Valid: true, String: input.Country},
		State:        sql.NullString{Valid: true, String: input.State},
		Role:         "user", // default role
	}

	_, err = s.Provider.CreateUser(context.Background(), &params)
	if err != nil {
		log.Println("failed to create user: " + err.Error())
		RespondWithError(w, http.StatusInternalServerError, "failed to create user: ")
		return
	}

	RespondWithJson(w, http.StatusOK, "signup successful")
}
