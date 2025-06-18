package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	db "go-google-login/database"
	"go-google-login/utils"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

var googleOauthConfig oauth2.Config

// oauthStateString is used to validate the OAuth2 state parameter
var oauthStateString = uuid.New().String()

type GoogleLoginController struct{}
type CookieController struct{}


func (g *GoogleLoginController) GoogleHandleLogin(w http.ResponseWriter, r *http.Request) {
	g.GoogleConfig()
	url := googleOauthConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline) // Generate the URL for Google's OAuth 2.0 server with the state parameter
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) // Redirect the user to Google's OAuth 2.0 server
}

func (g *GoogleLoginController) GoogleConfig() {
	googleOauthConfig = oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/api/callback-gl", os.Getenv("DEV_URL")),
		ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),

		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile", // Scopes for email and profile information
		},
		Endpoint: google.Endpoint, //google OAuth2 endpoint
	}
}

func (g *GoogleLoginController) HandleCallback(w http.ResponseWriter, r *http.Request) {

	// Get the 'state' parameter from the callback URL
	state := r.URL.Query().Get("state")
	// Check if the state matches the expected value to prevent CSRF(Cross-Site Request Forgery) attacks
	if state != oauthStateString {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		RedirectWithError(w, r, fmt.Errorf("invalid OAuth state"))
		return
	}
	// Get the 'code' parameter from the callback URL
	code := r.URL.Query().Get("code")
	// If code is missing, return an error
	if code == "" {
		RedirectWithError(w, r, fmt.Errorf("code not found"))
		return
	}

	// Exchange the authorization code for an access token and ID token
	token, err := googleOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("Failed to exchange token: %v", err)
		http.Error(w, fmt.Sprintf("Failed to exchange token: %v"+err.Error(), err), http.StatusInternalServerError)
		RedirectWithError(w, r, fmt.Errorf("failed to exchange token: %v", err))
		return
	}

	// Extract and verify the ID token from the token response
	payload, err := VerifyGoogleToken(token.Extra("id_token").(string))
	if err != nil {
		log.Printf("Failed to verify token: %v", err)
		http.Error(w, "Failed to verify token", http.StatusInternalServerError)
		RedirectWithError(w, r, fmt.Errorf("failed to verify token"))
		return
	}

	// Extract the user's email from the ID token payload
	email := payload.Claims["email"].(string)

	// Process the user token (create session, set cookies, etc.)
	ProcessUserToken(w, r, email, token.AccessToken)
}

func ProcessUserToken(w http.ResponseWriter, r *http.Request, email string, gtoken string) {
	// Initialize the database connection
	db, err := db.Init()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Query the user by email
	var userID, userName, fullName string
	cookieController := CookieController{}
	err = db.QueryRow("SELECT user_id, user_name, full_name FROM users WHERE email = ?", email).Scan(&userID, &userName, &fullName)
	if err != nil {
		http.Redirect(w, r, os.Getenv("FRONTEND_URL"), http.StatusFound)
		http.Error(w, "Email not found in database", http.StatusUnauthorized)
		return
	}
	// Create a user struct for JWT generation
	user := utils.User{
		UserID:      userID,
		GoogleOAuth: gtoken,
		UserName:    userName,
		Email:       email,
		FullName:    fullName,
	}
	// Generate a JWT token for the user
	tokenString, err := utils.GenerateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
		return
	}

	// Optionally set the token in the Authorization header
	r.Header.Set("Authorization", "Bearer "+tokenString)

	// Set the JWT as a secure cookie
	cookieController.SetCookie(w, tokenString, "")
	// Redirect to the frontend after successful login
	http.Redirect(w, r, os.Getenv("FRONTEND_URL"), http.StatusFound)

	// Also return the token as JSON (optional)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func RedirectWithError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func VerifyGoogleToken(tokenString string) (*idtoken.Payload, error) {
	ctx := context.Background()
	payload, err := idtoken.Validate(ctx, tokenString, os.Getenv("GOOGLE_OAUTH_CLIENT_ID"))
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	return payload, nil
}

func (g *GoogleLoginController) RevokeGoogleToken(tokenString string) error {
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: tokenString,
	}))

	revokeURL := fmt.Sprintf(os.Getenv("REVOKE_URL")+"%s", tokenString)
	resp, err := client.Get(revokeURL)
	if err != nil {
		return fmt.Errorf("could not revoke token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to revoke token, status: %v", resp.Status)
	}

	log.Println("Token revoked successfully")
	return nil
}
