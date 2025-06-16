package utils

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	InvalidatedTokens = make(map[string]time.Time)
	tokenMutex        sync.RWMutex
)

type User struct {
	UserID      string
	GoogleOAuth string
	UserName    string
	Email       string
	FullName    string
}

type Claims struct {
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	Email       string `json:"email"`
	FullName    string `json:"full_name"`
	GoogleOAuth string `json:"google_oauth"`
	jwt.RegisteredClaims
}

// GenerateToken creates a signed JWT for a user
func GenerateToken(user User) (string, error) {
	// Create claims with user info and expiration
	claims := &Claims{
		UserID:      user.UserID,      // set user ID
		GoogleOAuth: user.GoogleOAuth, // set Google OAuth token
		UserName:    user.UserName,    // set username
		Email:       user.Email,       // set email
		FullName:    user.FullName,    // set full name
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // set expiration to 24 hours from now
			IssuedAt:  jwt.NewNumericDate(time.Now()),                     // set issued at to now
		},
	}
	// Create a new JWT token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign the token with the secret key from environment variable
	return token.SignedString([]byte(os.Getenv("JWT_SECRET_KEY")))
}

// ValidateToken parses and validates a JWT, returning its claims
func ValidateToken(tokenString string, secretKey []byte) (jwt.MapClaims, error) {
	// Check if the token has been invalidated
	if IsTokenInvalidated(tokenString) {
		return nil, fmt.Errorf("token has been invalidated") // return error if token is invalidated
	}
	// Parse the JWT token using the provided secret key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil // return the secret key for validation
	})
	// Return error if parsing fails
	if err != nil {
		return nil, fmt.Errorf("Invalid token: %v", err)
	}
	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	// Check if claims are valid and token is valid
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	// Check token expiration
	if exp, ok := claims["exp"].(float64); ok {
		if float64(time.Now().Unix()) >= exp {
			return nil, fmt.Errorf("token has expired") // return error if token is expired
		}
	}
	// Return the claims if everything is valid
	return claims, nil
}

func InvalidateToken(tokenString string) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	InvalidatedTokens[tokenString] = time.Now().Add(24 * time.Hour)
}

func IsTokenInvalidated(tokenString string) bool {
	tokenMutex.RLock()
	defer tokenMutex.RUnlock()
	_, exists := InvalidatedTokens[tokenString]
	return exists
}

// ExpireToken sets the token's expiration to now and invalidates it
func ExpireToken(tokenString string) error {
	// Validate the token using the secret key from environment variable
	claims, err := ValidateToken(tokenString, []byte(os.Getenv("JWT_SECRET_KEY")))
	if err != nil {
		return err
	}
	// Set the 'exp' claim to the current Unix time (expire immediately)
	claims["exp"] = time.Now().Unix()
	// Add the token to the invalidated tokens map
	InvalidateToken(tokenString)
	return nil
}
