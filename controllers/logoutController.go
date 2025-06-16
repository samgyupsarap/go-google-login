package controllers
import (
	"go-google-login/utils"
	"encoding/json"
	"net/http"
	"os"
	"strings"

)

type LogoutController struct{}

func (l *LogoutController) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	var mySigningKey = []byte(os.Getenv("JWT_SECRET_KEY"))

	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenString == "" {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	claims, err := utils.ValidateToken(tokenString, mySigningKey)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if gauthToken, ok := claims["google_oauth"].(string); ok && gauthToken != "" {
		GoogleLoginController := GoogleLoginController{}
		GoogleLoginController.RevokeGoogleToken(gauthToken)
	}

	cookies := []string{"token"}
	for _, cookieName := range cookies {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
		})
	}

	if err := utils.ExpireToken(tokenString); err != nil {
		http.Error(w, "Failed to expire token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Logout successful",
	})
}
