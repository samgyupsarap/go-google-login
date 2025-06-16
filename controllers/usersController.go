package controllers

import (
    "encoding/json"
    "net/http"
    "go-google-login/database"
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

    rows, err := db.Query("SELECT user_id, user_name, email, full_name, google_oauth FROM users")
    if err != nil {
        http.Error(w, "Query error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        if err := rows.Scan(&user.UserID, &user.UserName, &user.Email, &user.FullName, &user.GoogleOAuth); err != nil {
            http.Error(w, "Scan error", http.StatusInternalServerError)
            return
        }
        users = append(users, user)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}