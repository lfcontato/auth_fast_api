// Caminho: internal/db/migrate.go
// Resumo: Migrações mínimas para criar tabelas necessárias (admins, admins_sessions_local).

package db

import (
    "context"
    "database/sql"
)

// Migrate aplica o schema mínimo necessário para operação básica de autenticação.
func Migrate(ctx context.Context, sqldb *sql.DB) error {
    var stmts []string
    if IsPostgres() {
        stmts = []string{
            `CREATE TABLE IF NOT EXISTS admins (
                id BIGSERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                system_role TEXT NOT NULL,
                subscription_plan TEXT NOT NULL DEFAULT 'monthly',
                expires_at TIMESTAMPTZ NULL,
                is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                owner_id BIGINT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE TABLE IF NOT EXISTS admins_sessions_local (
                id BIGSERIAL PRIMARY KEY,
                admin_id BIGINT NOT NULL REFERENCES admins(id),
                session_id TEXT NOT NULL UNIQUE,
                family_id TEXT NOT NULL,
                refresh_token_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                revoked_at TIMESTAMPTZ NULL,
                revoked_reason TEXT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_admins_sessions_admin_id ON admins_sessions_local(admin_id);`,
            `CREATE TABLE IF NOT EXISTS admins_verifications (
                id BIGSERIAL PRIMARY KEY,
                admin_id BIGINT NOT NULL REFERENCES admins(id),
                code TEXT NOT NULL UNIQUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NULL,
                consumed_at TIMESTAMPTZ NULL
            );`,
            `CREATE INDEX IF NOT EXISTS idx_admins_verifications_admin_id ON admins_verifications(admin_id);`,
        }
    } else {
        stmts = []string{
            `CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                system_role TEXT NOT NULL,
                subscription_plan TEXT NOT NULL DEFAULT 'monthly',
                expires_at TIMESTAMP NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                owner_id INTEGER NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE TABLE IF NOT EXISTS admins_sessions_local (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                family_id TEXT NOT NULL,
                refresh_token_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP NULL,
                revoked_reason TEXT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(session_id),
                FOREIGN KEY(admin_id) REFERENCES admins(id)
            );`,
            `CREATE INDEX IF NOT EXISTS idx_admins_sessions_admin_id ON admins_sessions_local(admin_id);`,
            `CREATE TABLE IF NOT EXISTS admins_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                code TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                consumed_at TIMESTAMP NULL,
                FOREIGN KEY(admin_id) REFERENCES admins(id)
            );`,
            `CREATE INDEX IF NOT EXISTS idx_admins_verifications_admin_id ON admins_verifications(admin_id);`,
        }
    }

    for _, s := range stmts {
        if _, err := sqldb.ExecContext(ctx, s); err != nil {
            return err
        }
    }

    // Best-effort ALTERs to add new columns on existing schemas; ignore errors if columns already exist
    if IsPostgres() {
        _, _ = sqldb.ExecContext(ctx, `ALTER TABLE admins ADD COLUMN IF NOT EXISTS subscription_plan TEXT NOT NULL DEFAULT 'monthly'`)
        _, _ = sqldb.ExecContext(ctx, `ALTER TABLE admins ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL`)
        _, _ = sqldb.ExecContext(ctx, `ALTER TABLE admins_verifications ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL`)
    } else {
        _, _ = sqldb.ExecContext(ctx, `ALTER TABLE admins ADD COLUMN subscription_plan TEXT NOT NULL DEFAULT 'monthly'`)
        _, _ = sqldb.ExecContext(ctx, `ALTER TABLE admins ADD COLUMN expires_at TIMESTAMP NULL`)
        _, _ = sqldb.ExecContext(ctx, `ALTER TABLE admins_verifications ADD COLUMN expires_at TIMESTAMP NULL`)
    }
    return nil
}
