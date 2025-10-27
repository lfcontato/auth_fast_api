package httpapi

import (
    "net/http"
    "strings"
)

// handleAdminRoutes roteia chamadas do domínio Admin.
// Retorna true quando a rota foi atendida.
func handleAdminRoutes(w http.ResponseWriter, r *http.Request) bool {
    path := r.URL.Path
    switch {
    case path == "/admin/auth/token" && r.Method == http.MethodPost:
        adminHandleAuthToken(w, r); return true
    case path == "/admin/auth/token/refresh" && r.Method == http.MethodPost:
        adminHandleAuthRefresh(w, r); return true
    case path == "/admin/auth/mfa/verify" && r.Method == http.MethodPost:
        adminHandleMFAVerify(w, r); return true
    case path == "/admin/auth/password-recovery" && r.Method == http.MethodPost:
        adminHandlePasswordRecovery(w, r); return true
    case path == "/admin/auth/verification-code" && r.Method == http.MethodPost:
        adminHandleVerificationCodeResend(w, r); return true
    case strings.HasPrefix(path, "/admin/auth/verify-code/") && r.Method == http.MethodPost:
        code := strings.TrimPrefix(path, "/admin/auth/verify-code/")
        adminHandleVerifyCodeURL(w, r, code); return true
    case path == "/admin/auth/verify" && r.Method == http.MethodPost:
        adminHandleVerify(w, r); return true
    case (path == "/admin" || path == "/admin/") && r.Method == http.MethodPost:
        adminHandleCreate(w, r); return true
    case (path == "/admin" || path == "/admin/") && r.Method == http.MethodGet:
        adminHandleList(w, r); return true
    case strings.HasPrefix(path, "/admin/") && strings.HasSuffix(path, "/subscription-plan") && r.Method == http.MethodPatch:
        adminHandleUpdatePlan(w, r); return true
    case strings.HasPrefix(path, "/admin/") && strings.HasSuffix(path, "/system-role") && r.Method == http.MethodPatch:
        adminHandleUpdateRole(w, r); return true
    case path == "/admin/password" && r.Method == http.MethodPatch:
        adminHandleChangeOwnPassword(w, r); return true
    case path == "/admin/mcp/token" && r.Method == http.MethodPost:
        adminHandleCreateAPIToken(w, r); return true
    }
    return false
}
