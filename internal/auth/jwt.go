// Caminho: internal/auth/jwt.go
// Resumo: Utilidades de JWT (assinatura e verificação). Interface e stubs para integração futura
// usando algoritmo HMAC (ex.: HS256), sem dependências externas neste momento.

package auth

import (
    "time"
)

// Claims representa o conjunto mínimo de claims usadas no serviço.
type Claims struct {
    Subject string            // sub
    SessionID string          // sid
    SystemRole string         // sro
    Workspaces map[string]string // wss (hash_id -> resource_role)
    ExpiresAt time.Time       // exp
}

// Sign assina claims e retorna o token JWT serializado.
// Implementação real pendente (usar biblioteca JWT ou implementação própria segura).
func Sign(secret, algorithm string, c Claims) (string, error) {
    return "", ErrNotImplemented
}

// Verify valida a assinatura e expiração de um token JWT.
// Retorna as claims decodificadas se válido.
func Verify(secret string, token string) (Claims, error) {
    return Claims{}, ErrNotImplemented
}

// ErrNotImplemented indica funcionalidade ainda não implementada.
var ErrNotImplemented = Err("not implemented")

// Err é um erro simples baseado em string.
type Err string

// Error retorna a mensagem do erro.
func (e Err) Error() string { return string(e) }

