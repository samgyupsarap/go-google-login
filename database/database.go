package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

var DB *sql.DB

func Init() (*sql.DB, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("error loading .env file: %v", err)
	}

	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASSWORD")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	name := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, pass, host, port, name)

	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open error: %v", err)
	}

	if err = DB.Ping(); err != nil {
		return nil, fmt.Errorf("db.Ping error: %v", err)
	}

	log.Println("✅ Database connected successfully.")
	return DB, nil
}
