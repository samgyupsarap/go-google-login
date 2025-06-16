package main

import (
	"fmt"
	db "go-google-login/database"
	"go-google-login/routes"
	"log"
	"net/http"
)

func main() {
	router := routes.SetupRoutes()

	database, err := db.Init()
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer database.Close()

	// Add CORS middleware
	corsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		} 
		router.ServeHTTP(w, r)
	})

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "pong")
	})

	port := ":8080"
	fmt.Println("Starting server at", port)
	if err := http.ListenAndServe(port, corsHandler); err != nil {
		log.Fatal("Server failed:", err)
	}
}
