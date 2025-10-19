// Caminho: internal/db/dsn.go
// Resumo: Utilidades para interpretar DATABASE_URL e produzir DSN apropriado para drivers suportados.

package db

import (
    "fmt"
    "net/url"
    "strings"
)

// Driver representa os drivers suportados.
type Driver string

const (
    DriverSQLite  Driver = "sqlite"
    DriverPostgres Driver = "pgx"
)

// ParseDSN interpreta DATABASE_URL e retorna o driver e o DSN compatível com database/sql.
// Suporta esquemas: sqlite:///path.db e postgres://...
func ParseDSN(databaseURL string) (Driver, string) {
    if databaseURL == "" {
        // Default para SQLite em arquivo local
        return DriverSQLite, "file:auth_fast_api.db?cache=shared&mode=rwc&_pragma=busy_timeout(5000)"
    }

    // Normaliza casos comuns (ex.: "sqlite:///file.db")
    if strings.HasPrefix(databaseURL, "sqlite://") {
        // Remover prefixo sqlite:// e construir DSN para modernc sqlite
        // Formatos aceitos: sqlite:///absolute/path.db ou sqlite://relative/path.db
        u := strings.TrimPrefix(databaseURL, "sqlite://")
        u = strings.TrimPrefix(u, "/") // aceita com 3 barras
        // Usar file:<path> com pragmas
        return DriverSQLite, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_pragma=busy_timeout(5000)", u)
    }

    if strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://") {
        // pgx aceita DSN URL nativamente
        return DriverPostgres, databaseURL
    }

    // Tenta parsear como URL genericamente para decidir
    if u, err := url.Parse(databaseURL); err == nil && u.Scheme != "" {
        switch u.Scheme {
        case "sqlite":
            path := strings.TrimPrefix(databaseURL, "sqlite://")
            path = strings.TrimPrefix(path, "/")
            return DriverSQLite, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_pragma=busy_timeout(5000)", path)
        case "postgres", "postgresql":
            return DriverPostgres, databaseURL
        }
    }

    // Fallback: tratar como caminho de arquivo SQLite
    return DriverSQLite, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_pragma=busy_timeout(5000)", databaseURL)
}

