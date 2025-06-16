package middleware

import (
	"net/http"
	"go-google-login/utils"
	"strings"
	"os"
)

type Middleware struct {}

func (mw *Middleware) BearerTokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var mySigningKey = []byte(os.Getenv("JWT_SECRET_KEY"))

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")


		_, err := utils.ValidateToken(tokenString, mySigningKey)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}