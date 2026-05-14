package goauth

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/markbates/goth/gothic"
)

func (s *AuthService) GoogleAuthCallback(w http.ResponseWriter, r *http.Request, provider string) {
	// provider := "google"
	// log.Println("Cookies received:", r.Cookies())
	r = r.WithContext(context.WithValue(r.Context(), "provider", provider))

	googleUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusUnauthorized, "Google auth failed")
		return
	}

	// 1. Check if user exists by email
	existingUser, err := s.Provider.GetByEmail(r.Context(), googleUser.Email)
	// log.Printf("Google user: %+v\n", googleUser)
	// log.Printf("uSER LOCATION TO GET PARSE LOGIC: %v\n", googleUser.Location)
	// log.Printf("Avatar url: %v\n", googleUser.AvatarURL)

	// PARSE THE LOCATION FIELD TO EXTRACT COUNTRY AND STATE AND ADDRESS

	if err == nil {
		// USER EXISTS: Logic to link or "Upgrade"
		err = s.Provider.UpdateUserForOAuth(r.Context(), &UpdateUserForOAuthParams{
			ID:              existingUser.ID,
			GoogleID:        sql.NullString{String: googleUser.UserID, Valid: true},
			IsEmailVerified: sql.NullBool{Bool: true, Valid: true},
			AvatarUrl:       sql.NullString{String: googleUser.AvatarURL, Valid: googleUser.AvatarURL != ""},
		})
		if err != nil {
			RespondWithError(w, http.StatusInternalServerError, "Failed to link Google account")
			return
		}
	} else {

		params := CreateUserParams{
			Email:           strings.ToLower(googleUser.Email),
			FirstName:       googleUser.FirstName,
			LastName:        googleUser.LastName,
			PasswordHash:    sql.NullString{Valid: false}, // No password
			GoogleID:        sql.NullString{String: googleUser.UserID, Valid: true},
			IsEmailVerified: sql.NullBool{Bool: true, Valid: true},
			AvatarUrl:       sql.NullString{String: googleUser.AvatarURL, Valid: googleUser.AvatarURL != ""},
			Role:            "user",
		}
		existingUser, err = s.Provider.CreateUser(r.Context(), &params)
		if err != nil {
			log.Println("failed to create user: " + err.Error())
			RespondWithError(w, http.StatusInternalServerError, "failed to create user: ")
			return
		}
	}

	// Generate your JWT session here before redirecting
	// 1. Generate Fingerprint (Just like your LoginHandler)
	fingerprint, err := GenerateFingerprint()
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error generating fingerprint")
		return
	}

	// 2. Generate Access Token
	accessToken, err := MakeJwtTokenString(s, existingUser.ID.String(), fingerprint, s.AccessExpiry)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error generating tokens")
		return
	}

	// 3. Create Refresh Token (This sets the HttpOnly Cookie)
	_, err = CreateRefreshToken(s, existingUser.ID, fingerprint, w)
	if err != nil {
		RespondWithError(w, http.StatusInternalServerError, "error generating refresh session")
		return
	}

	// 4. Redirect to Frontend with the Access Token
	// We send the access token in the URL so the frontend can "pick it up"
	frontendUrl := "http://localhost:5173/auth/callback"
	if s.IsProduction {
		frontendUrl = "https://n3xtbridge.com/auth/callback"
	}

	finalRedirect := fmt.Sprintf("%s?token=%s", frontendUrl, accessToken)
	http.Redirect(w, r, finalRedirect, http.StatusFound)
}
