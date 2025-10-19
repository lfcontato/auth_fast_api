// Caminho: cmd/devseed/main.go
// Resumo: Utilitário de desenvolvimento para criar o usuário ROOT do .env e autenticar, exibindo os tokens.

package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/joho/godotenv"
    "golang.org/x/crypto/bcrypt"

    "github.com/lfcontato/auth_fast_api/internal/config"
    "github.com/lfcontato/auth_fast_api/internal/db"
    authsvc "github.com/lfcontato/auth_fast_api/internal/services/auth"
)

func main() {
    _ = godotenv.Load()
    cfg := config.Load()
    dbURL := os.Getenv("DATABASE_URL")
    if dbURL == "" { dbURL = cfg.DatabaseURL }

    sqldb, err := db.Connect(dbURL)
    if err != nil { log.Fatalf("db connect: %v", err) }
    if err := db.Migrate(context.Background(), sqldb); err != nil { log.Fatalf("migrate: %v", err) }

    seedRoot(sqldb)

    accessTTL := time.Duration(getInt("TOKEN_ACCESS_EXPIRE_SECONDS", 1800)) * time.Second
    refreshTTL := time.Duration(getInt("TOKEN_REFRESH_EXPIRE_SECONDS", 2592000)) * time.Second
    svc := authsvc.New(sqldb, cfg.SecretKey, accessTTL, refreshTTL)

    user := os.Getenv("ROOT_AUTH_USER")
    pass := os.Getenv("ROOT_AUTH_PASSWORD")
    access, refresh, err := svc.Login(context.Background(), user, pass)
    if err != nil {
        log.Fatalf("login error: %v", err)
    }
    fmt.Println("ACCESS_TOKEN=", access)
    fmt.Println("REFRESH_TOKEN=", refresh)
}

func seedRoot(sqldb *sql.DB) {
    user := os.Getenv("ROOT_AUTH_USER")
    email := os.Getenv("ROOT_AUTH_EMAIL")
    pass := os.Getenv("ROOT_AUTH_PASSWORD")
    if user == "" || email == "" || pass == "" {
        log.Println("ROOT_AUTH_* não definidos, omitindo seed")
        return
    }
    var count int
    _ = sqldb.QueryRow(`SELECT COUNT(1) FROM admins WHERE username = ?`, user).Scan(&count)
    if count > 0 { 
        log.Println("Usuário root já existe, pulando criação")
        return 
    }
    hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
    if _, err := sqldb.Exec(`INSERT INTO admins (email, username, password_hash, system_role, is_verified) VALUES (?,?,?,?,1)`, email, user, string(hash), "root"); err != nil {
        log.Fatalf("seed root failed: %v", err)
    }
    log.Println("Usuário root criado com sucesso")
}

func getInt(key string, def int) int {
    if v := os.Getenv(key); v != "" {
        var n int
        _, err := fmt.Sscanf(v, "%d", &n)
        if err == nil { return n }
    }
    return def
}

