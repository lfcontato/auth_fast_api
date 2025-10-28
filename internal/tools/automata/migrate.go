// Caminho: internal/tools/automata/migrate.go
// Resumo: Migrações mínimas para o Automata (stubs): chaves, prompts, chats.

package automata

import (
    "context"
    "database/sql"
)

// Migrate cria as tabelas básicas do Automata (opcional para stubs).
func Migrate(ctx context.Context, db *sql.DB, isPostgres bool) error {
    var stmts []string
    if isPostgres {
        stmts = []string{
            `CREATE TABLE IF NOT EXISTS automata_api_keys (
                id BIGSERIAL PRIMARY KEY,
                space_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                provider TEXT NOT NULL,
                name TEXT NULL,
                api_key TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_automata_api_keys_space_user ON automata_api_keys(space_id, user_id);`,
            `CREATE TABLE IF NOT EXISTS automata_prompts (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                api_key_id BIGINT NULL,
                provider TEXT NULL,
                name TEXT NOT NULL,
                description TEXT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_automata_prompts_user ON automata_prompts(user_id);`,
            `CREATE TABLE IF NOT EXISTS automata_chats (
                id BIGSERIAL PRIMARY KEY,
                space_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                prompt_id BIGINT NULL,
                message TEXT NOT NULL,
                response TEXT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_automata_chats_space_user ON automata_chats(space_id, user_id);`,
        }
    } else {
        stmts = []string{
            `CREATE TABLE IF NOT EXISTS automata_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                space_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                name TEXT NULL,
                api_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE INDEX IF NOT EXISTS idx_automata_api_keys_space_user ON automata_api_keys(space_id, user_id);`,
            `CREATE TABLE IF NOT EXISTS automata_prompts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                api_key_id INTEGER NULL,
                provider TEXT NULL,
                name TEXT NOT NULL,
                description TEXT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE INDEX IF NOT EXISTS idx_automata_prompts_user ON automata_prompts(user_id);`,
            `CREATE TABLE IF NOT EXISTS automata_chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                space_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                prompt_id INTEGER NULL,
                message TEXT NOT NULL,
                response TEXT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE INDEX IF NOT EXISTS idx_automata_chats_space_user ON automata_chats(space_id, user_id);`,
        }
    }
    for _, s := range stmts {
        if _, err := db.ExecContext(ctx, s); err != nil {
            return err
        }
    }
    // Best-effort ALTERs para esquemas existentes
    if isPostgres {
        _, _ = db.ExecContext(ctx, `ALTER TABLE automata_api_keys ADD COLUMN IF NOT EXISTS space_id BIGINT`)
        _, _ = db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_automata_api_keys_space_user ON automata_api_keys(space_id, user_id)`)
    } else {
        _, _ = db.ExecContext(ctx, `ALTER TABLE automata_api_keys ADD COLUMN space_id INTEGER`)
        _, _ = db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_automata_api_keys_space_user ON automata_api_keys(space_id, user_id)`)
    }
    return nil
}
