package controllers

import (
	"database/sql"
	"encoding/json"
	db "go-google-login/database"
	"go-google-login/utils"
	"net/http"
	"os"
	"strings"
)

type User struct {
	UserID      int    `json:"user_id"`
	UserName    string `json:"user_name"`
	Email       string `json:"email"`
	FullName    string `json:"full_name"`
	GoogleOAuth string `json:"google_oauth"`
}

type UserController struct{}

func (u *UserController) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	db, err := db.Init()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT user_id, user_name, email, full_name FROM users")
	if err != nil {
		http.Error(w, "Query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.UserID, &user.UserName, &user.Email, &user.FullName); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (u *UserController) GetUserByID(w http.ResponseWriter, r *http.Request) {
	// Implementation for getting a user by ID
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := utils.ValidateToken(tokenString, []byte(os.Getenv("JWT_SECRET_KEY")))
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	userID, ok := claims["user_id"].(string)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	db, err := db.Init()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT user_id, user_name, email, full_name FROM users WHERE user_id = ?", userID).Scan(&user.UserID, &user.UserName, &user.Email, &user.FullName)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, "Query error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
