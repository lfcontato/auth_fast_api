// Caminho: internal/tools/faciendum/migrate.go
// Resumo: Migrações do banco do Faciendum (boards, tracks, tasks).

package faciendum

import (
    "context"
    "database/sql"
)

// Migrate cria as tabelas necessárias no banco do Faciendum.
func Migrate(ctx context.Context, db *sql.DB, isPostgres bool) error {
    var stmts []string
    if isPostgres {
        stmts = []string{
            `CREATE TABLE IF NOT EXISTS faciendum_boards (
                id BIGSERIAL PRIMARY KEY,
                space_id BIGINT NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_faciendum_boards_space_id ON faciendum_boards(space_id);`,
            `CREATE TABLE IF NOT EXISTS faciendum_tracks (
                id BIGSERIAL PRIMARY KEY,
                board_id BIGINT NOT NULL,
                name TEXT NOT NULL,
                position INT NOT NULL,
                is_final BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_faciendum_tracks_board_id ON faciendum_tracks(board_id);`,
            `CREATE TABLE IF NOT EXISTS faciendum_tasks (
                id BIGSERIAL PRIMARY KEY,
                space_id BIGINT NOT NULL,
                board_id BIGINT NOT NULL,
                track_id BIGINT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NULL,
                position INT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );`,
            `CREATE INDEX IF NOT EXISTS idx_faciendum_tasks_space_board ON faciendum_tasks(space_id, board_id);`,
        }
    } else {
        stmts = []string{
            `CREATE TABLE IF NOT EXISTS faciendum_boards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                space_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE INDEX IF NOT EXISTS idx_faciendum_boards_space_id ON faciendum_boards(space_id);`,
            `CREATE TABLE IF NOT EXISTS faciendum_tracks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                board_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                position INTEGER NOT NULL,
                is_final BOOLEAN NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE INDEX IF NOT EXISTS idx_faciendum_tracks_board_id ON faciendum_tracks(board_id);`,
            `CREATE TABLE IF NOT EXISTS faciendum_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                space_id INTEGER NOT NULL,
                board_id INTEGER NOT NULL,
                track_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NULL,
                position INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );`,
            `CREATE INDEX IF NOT EXISTS idx_faciendum_tasks_space_board ON faciendum_tasks(space_id, board_id);`,
        }
    }
    for _, s := range stmts {
        if _, err := db.ExecContext(ctx, s); err != nil { return err }
    }
    return nil
}

