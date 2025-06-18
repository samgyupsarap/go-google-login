package controllers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"time"
)

// Response struct for JSON responses
type Response struct {
	Message string `json:"message"`
	Token   string `json:"token"`
}

// SetCookie sets a secure, HttpOnly cookie with the encrypted JWT token
func (c *CookieController) SetCookie(w http.ResponseWriter, jwt string, errorMessage string) {
	// Only set cookie if there is no error message
	if errorMessage == "" {
		// Derive a 32-byte key from the JWT secret using SHA-256
		secretKey := sha256.Sum256([]byte(os.Getenv("JWT_SECRET_KEY")))
		// Encrypt the JWT token using AES-GCM
		encryptedToken, err := EncryptToken(jwt, secretKey[:])
		if err != nil {
			// Return error if encryption fails
			http.Error(w, "Error encrypting token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Set the encrypted token as a cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    encryptedToken,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour), // Cookie expires in 24 hours
			Secure:   true,                           // Only sent over HTTPS
			HttpOnly: true,                           // Not accessible via JavaScript
			SameSite: http.SameSiteStrictMode,        // Strict same-site policy
		})
		return
	}
}

// GetCookie retrieves and decrypts the JWT token from the cookie
func (c *CookieController) GetCookie(w http.ResponseWriter, r *http.Request) {
	// Derive the key from the JWT secret
	secretKey := sha256.Sum256([]byte(os.Getenv("JWT_SECRET_KEY")))

	// Retrieve the token cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// No cookie found
			http.Error(w, "No cookie found", http.StatusUnauthorized)
			return
		}
		// Other error retrieving cookie
		http.Error(w, "Error retrieving cookie: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Decrypt the token using the derived key
	decryptedToken, err := DecryptToken(cookie.Value, secretKey[:])
	if err != nil {
		// Error decrypting token
		http.Error(w, "Error decrypting token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare the response
	resp := &Response{
		Message: "Cookie retrieved successfully",
		Token:   decryptedToken,
	}

	// Set response headers and write JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// DeleteCookie removes the token and error cookies from the browser
func (c *CookieController) DeleteCookie(w http.ResponseWriter, r *http.Request) {
	// Delete the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // Expire immediately
		MaxAge:   -1,              // Ensure deletion
		HttpOnly: true,            // HttpOnly for security
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	// Delete the error cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "error",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // Expire immediately
		MaxAge:   -1,              // Ensure deletion
		HttpOnly: false,           // Not HttpOnly
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// EncryptToken uses AES-GCM with a random nonce and a provided key to encrypt the token
func EncryptToken(token string, key []byte) (string, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Generate a random nonce(IV)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// Seal (encrypt) the token with the nonce
	ciphertext := gcm.Seal(nonce, nonce, []byte(token), nil)
	// Encode the ciphertext as base64 for storage in the cookie
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptToken uses AES-GCM with nonce and a provided key to decrypt the token
func DecryptToken(encoded string, key []byte) (string, error) {
	// Decode the base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// Create a new GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Check that the ciphertext is long enough for the nonce
	if len(ciphertext) < gcm.NonceSize() {
		return "", err
	}
	// Extract the nonce from the ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	// Return the decrypted token as a string
	return string(plaintext), nil
}
