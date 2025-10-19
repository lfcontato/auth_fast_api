// Caminho: internal/domain/models.go
// Resumo: Modelos de domínio e erros centrais do sistema (Admin, Sessões) usados por serviços.

package domain

import (
    "errors"
    "time"
)

// Admin representa um administrador do sistema.
type Admin struct {
    ID           int64
    Email        string
    Username     string
    PasswordHash string
    SystemRole   string
    SubscriptionPlan string
    ExpiresAt    *time.Time
    IsVerified   bool
    OwnerID      *int64
    CreatedAt    time.Time
    UpdatedAt    time.Time
}

// AdminSession representa uma sessão de administrador e o ciclo de vida do refresh token.
type AdminSession struct {
    ID               int64
    AdminID          int64
    SessionID        string
    FamilyID         string
    RefreshTokenHash string
    ExpiresAt        time.Time
    RevokedAt        *time.Time
    RevokedReason    *string
    CreatedAt        time.Time
}

// Erros comuns de domínio.
var (
    ErrInvalidCredentials = errors.New("invalid credentials")
    ErrUnauthorized       = errors.New("unauthorized")
    ErrNotFound           = errors.New("not found")
)
