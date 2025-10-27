package httpapi

import (
    "net/http"
)

// handleUserAuthRoutes roteia chamadas do domínio Users (autenticação).
// Retorna true quando a rota foi atendida.
func handleUserAuthRoutes(w http.ResponseWriter, r *http.Request) bool {
    path := r.URL.Path
    switch {
    case path == "/user" && r.Method == http.MethodPost:
        userHandleCreate(w, r); return true
    case path == "/user/auth/token" && r.Method == http.MethodPost:
        userHandleAuthToken(w, r); return true
    case path == "/user/auth/token/refresh" && r.Method == http.MethodPost:
        userHandleAuthRefresh(w, r); return true
    case path == "/user/auth/verify" && r.Method == http.MethodPost:
        userHandleAuthVerify(w, r); return true
    case path == "/user/auth/verify-link" && r.Method == http.MethodGet:
        userHandleAuthVerifyLink(w, r); return true
    case path == "/user/auth/password-recovery" && r.Method == http.MethodPost:
        userHandlePasswordRecovery(w, r); return true
    case path == "/user/auth/verification-code" && r.Method == http.MethodPost:
        userHandleVerificationCode(w, r); return true
    }
    return false
}
