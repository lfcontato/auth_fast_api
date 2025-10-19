// Caminho: internal/db/db.go
// Resumo: Responsável por expor uma função de conexão com o banco de dados.
// Implementação mínima com stub, para posterior integração com Postgres/SQLite.

package db

import (
    "database/sql"
    "fmt"
    _ "github.com/jackc/pgx/v5/stdlib" // registra driver pgx
    _ "modernc.org/sqlite"             // registra driver sqlite puro Go
)

// Connect estabelece a conexão com o banco de dados a partir de DATABASE_URL.
// Suporta postgres (pgx) e sqlite (modernc sqlite).
func Connect(databaseURL string) (*sql.DB, error) {
    driver, dsn := ParseDSN(databaseURL)
    db, err := sql.Open(string(driver), dsn)
    if err != nil {
        return nil, fmt.Errorf("open db: %w", err)
    }
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("ping db: %w", err)
    }
    setCurrentDriver(driver)
    return db, nil
}
