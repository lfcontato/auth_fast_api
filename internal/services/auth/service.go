// Caminho: internal/services/auth/service.go
// Resumo: Serviço de autenticação de administradores: login, emissão de tokens e refresh/rotação.

package authsvc

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "errors"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"

    "github.com/lfcontato/auth_fast_api/internal/domain"
    "github.com/lfcontato/auth_fast_api/internal/db"
)

// Service agrega dependências necessárias para autenticação.
type Service struct {
    DB              *sql.DB
    SecretKey       string
    AccessTTL       time.Duration
    RefreshTTL      time.Duration
}

// New cria uma instância do serviço de autenticação.
func New(db *sql.DB, secret string, accessTTL, refreshTTL time.Duration) *Service {
    return &Service{DB: db, SecretKey: secret, AccessTTL: accessTTL, RefreshTTL: refreshTTL}
}

// Login efetua autenticação por username/password e emite par de tokens.
func (s *Service) Login(ctx context.Context, username, password string) (access string, refresh string, err error) {
    var a domain.Admin
    q := db.Rebind(`SELECT id, email, username, password_hash, system_role, is_verified FROM admins WHERE username = ?`)
    row := s.DB.QueryRowContext(ctx, q, username)
    if err := row.Scan(&a.ID, &a.Email, &a.Username, &a.PasswordHash, &a.SystemRole, &a.IsVerified); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return "", "", domain.ErrInvalidCredentials
        }
        return "", "", err
    }
    if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) != nil {
        return "", "", domain.ErrInvalidCredentials
    }
    // Permitir login apenas para contas verificadas
    if !a.IsVerified {
        return "", "", domain.ErrUnauthorized
    }

    // Criar sessão + tokens
    sessionID := uuid.NewString()
    familyID := uuid.NewString()
    access, err = s.signAccessToken(a, sessionID)
    if err != nil { return "", "", err }
    refresh, err = generateRefreshToken()
    if err != nil { return "", "", err }

    // Persistir refresh hash
    hash := sha256.Sum256([]byte(refresh))
    expires := time.Now().Add(s.RefreshTTL)
    ins := db.Rebind(`INSERT INTO admins_sessions_local (admin_id, session_id, family_id, refresh_token_hash, expires_at) VALUES (?,?,?,?,?)`)
    if _, err := s.DB.ExecContext(ctx, ins, a.ID, sessionID, familyID, hex.EncodeToString(hash[:]), expires); err != nil {
        return "", "", fmt.Errorf("insert session: %w", err)
    }
    return access, refresh, nil
}

// Refresh valida o refresh token e emite um novo par, rotacionando o refresh.
func (s *Service) Refresh(ctx context.Context, refresh string) (access string, newRefresh string, err error) {
    if refresh == "" {
        return "", "", domain.ErrUnauthorized
    }
    hash := sha256.Sum256([]byte(refresh))
    var adminID int64
    var systemRole string
    var sessionID, familyID string
    // Encontra sessão ativa por hash e não expirada
    q := db.Rebind(`SELECT s.admin_id, a.system_role, s.session_id, s.family_id
          FROM admins_sessions_local s
          JOIN admins a ON a.id = s.admin_id
          WHERE s.refresh_token_hash = ?
            AND s.expires_at > CURRENT_TIMESTAMP
            AND s.revoked_at IS NULL
            AND a.is_verified = TRUE`)
    row := s.DB.QueryRowContext(ctx, q, hex.EncodeToString(hash[:]))
    if err := row.Scan(&adminID, &systemRole, &sessionID, &familyID); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return "", "", domain.ErrUnauthorized
        }
        return "", "", err
    }

    // Rotate: revoga atual e cria novo refresh
    now := time.Now()
    if _, err := s.DB.ExecContext(ctx, db.Rebind(`UPDATE admins_sessions_local SET revoked_at = ?, revoked_reason = ? WHERE refresh_token_hash = ?`), now, "rotated", hex.EncodeToString(hash[:])); err != nil {
        return "", "", err
    }
    // Emite novo access e refresh mantendo family_id, com novo session_id
    sessionID = uuid.NewString()
    access, err = s.signAccessToken(domain.Admin{ID: adminID, SystemRole: systemRole}, sessionID)
    if err != nil { return "", "", err }
    newRefresh, err = generateRefreshToken()
    if err != nil { return "", "", err }
    newHash := sha256.Sum256([]byte(newRefresh))
    expires := time.Now().Add(s.RefreshTTL)
    ins := db.Rebind(`INSERT INTO admins_sessions_local (admin_id, session_id, family_id, refresh_token_hash, expires_at) VALUES (?,?,?,?,?)`)
    if _, err := s.DB.ExecContext(ctx, ins, adminID, sessionID, familyID, hex.EncodeToString(newHash[:]), expires); err != nil {
        return "", "", err
    }
    return access, newRefresh, nil
}

// signAccessToken assina um JWT de acesso com claims mínimas.
func (s *Service) signAccessToken(a domain.Admin, sessionID string) (string, error) {
    claims := jwt.MapClaims{
        "sub": fmt.Sprintf("admin|%d", a.ID),
        "sid": sessionID,
        "sro": a.SystemRole,
        "wss": map[string]string{},
        "exp": time.Now().Add(s.AccessTTL).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(s.SecretKey))
}

// generateRefreshToken cria um token aleatório seguro em hex.
func generateRefreshToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil { return "", err }
    return hex.EncodeToString(b), nil
}
