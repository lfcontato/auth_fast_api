// Caminho: internal/handlers/admin_auth.go
// Resumo: Handlers de autenticação de administradores (login e refresh). Camada de apresentação
// que valida entrada e delega regras para serviços (a serem implementados). Mantém DTOs básicos.

package handlers

import (
    "context"
)

// AdminLoginRequest representa o payload de login de admin.
// Campos mínimos para autenticação por username/password.
type AdminLoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

// TokenPair representa o par de tokens retornados pelo login/refresh.
type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
}

// AdminLogin realiza a autenticação do administrador e retorna um par de tokens.
// Esta função deve validar credenciais e acionar serviços de sessão/JWT.
func AdminLogin(ctx context.Context, req AdminLoginRequest) (TokenPair, error) {
    // TODO: validar credenciais, consultar storage, gerar JWT e refresh
    return TokenPair{}, ErrNotImplemented
}

// AdminRefresh emite um novo par de tokens a partir de um Refresh Token válido.
// Deve validar família/rotação de refresh e emitir sessão renovada.
func AdminRefresh(ctx context.Context, refreshToken string) (TokenPair, error) {
    // TODO: validar refresh token e emitir novo par
    return TokenPair{}, ErrNotImplemented
}

// ErrNotImplemented sinaliza operações pendentes de implementação.
var ErrNotImplemented = Err("not implemented")

// Err é um tipo de erro simples baseado em string.
type Err string

// Error retorna a representação textual do erro.
func (e Err) Error() string { return string(e) }

