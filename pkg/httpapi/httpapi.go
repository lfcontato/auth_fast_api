// Caminho: pkg/httpapi/httpapi.go
// Resumo: Ponto de entrada HTTP compartilhado entre Vercel e servidor local, com todas as rotas da API.

package httpapi

import (
    "context"
    crand "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "math/big"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/joho/godotenv"
    "github.com/google/uuid"
	"github.com/lfcontato/auth_fast_api/internal/config"
	"github.com/lfcontato/auth_fast_api/internal/contants"
	"github.com/lfcontato/auth_fast_api/internal/db"
	"github.com/lfcontato/auth_fast_api/internal/kv"
	authsvc "github.com/lfcontato/auth_fast_api/internal/services/auth"
	emailsvc "github.com/lfcontato/auth_fast_api/internal/services/email"
    faciendum "github.com/lfcontato/auth_fast_api/internal/tools/faciendum"
    automata "github.com/lfcontato/auth_fast_api/internal/tools/automata"
	"golang.org/x/crypto/bcrypt"
)

// writeJSON escreve uma resposta JSON com status e payload arbitários.
// Ela define o cabeçalho Content-Type e serializa o objeto informado.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// healthHandler responde OK para verificação de saúde do serviço.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "auth_fast_api",
		"status":  "healthy",
	})
}

// rootHandler responde um resumo básico do serviço.
func rootHandler(w http.ResponseWriter, r *http.Request) {
    writeJSON(w, http.StatusOK, map[string]any{
        "ok":        true,
        "service":   "auth_fast_api",
        "version":   "0.1.0",
        "endpoints": []string{
            "/healthz",
            "/admin/auth/token",
            "/admin/auth/token/refresh",
            "/admin/auth/password-recovery",
            "/admin (GET)",
            "/user/auth/token",
            "/user/auth/token/refresh",
            "/user/auth/verify",
            "/user/auth/verify-link",
            "/user/auth/password-recovery",
            "/user/auth/verification-code",
            "/user/spaces",
        },
    })
}

// adminAuthTokenHandler é um stub do endpoint de login /admin/auth/token.
// Por enquanto retorna 501 (Not Implemented) até integração com serviços de autenticação.
func adminAuthTokenHandler_old(w http.ResponseWriter, r *http.Request) {
    if service == nil || sqldb == nil {
        logWarn("login attempted before service init")
        writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "AUTH_503_INIT", "message": "Serviço indisponível. Tente novamente."})
        return
    }
    // Rate limit + lockout
    ip := clientIP(r)
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:login:ip:"+ip, int64(cfg.LoginIPLimit), time.Duration(cfg.LoginIPWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_IP", "message": "Muitas tentativas. Tente mais tarde."})
        return
    }
    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_001", "message": "JSON inválido"})
		return
	}
    uname := strings.ToLower(strings.TrimSpace(req.Username))
    if locked, _ := kv.IsLocked(r.Context(), "lock:login:user:"+uname); locked {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_LOCK", "message": "Conta temporariamente bloqueada."})
        return
    }
    access, refresh, err := service.Login(r.Context(), uname, req.Password)
    if err != nil {
        logWarn("login failed for '%s': %v", req.Username, err)
        // incrementa falhas e possivelmente aplica lock
        if ok, n, _ := kv.AllowRate(r.Context(), "rl:loginfail:user:"+uname, int64(cfg.LoginFailLockThreshold), time.Duration(cfg.LoginFailLockTTLMinutes)*time.Minute); !ok || n >= int64(cfg.LoginFailLockThreshold) {
            _ = kv.SetLock(r.Context(), "lock:login:user:"+uname, time.Duration(cfg.LoginFailLockTTLMinutes)*time.Minute)
        }
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_001", "message": err.Error()})
        return
    }
    logInfo("login success for '%s'", req.Username)
    // reset counters em caso de sucesso
    kv.Del(r.Context(), "rl:loginfail:user:"+uname, "lock:login:user:"+uname)

    // MFA por e-mail: se habilitado, envia código e segura os tokens no Redis até verificação
    if cfg.MFAEmailEnabled {
        var (
            adminID int64
            email   string
        )
        if err := sqldb.QueryRow(db.Rebind(`SELECT id, email FROM admins WHERE username = ? LIMIT 1`), uname).Scan(&adminID, &email); err != nil {
            writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_MFA", "message": "Falha ao preparar MFA"})
            return
        }
        tx := uuid.NewString()
        code := generateNumericCode(cfg.MFACodeLength)
        ttl := time.Duration(cfg.MFACodeTTLMinutes) * time.Minute
        // Persistir tokens e código no Redis
        _ = kv.Set(r.Context(), "mfa:tx:"+tx, fmt.Sprintf(`{"access":"%s","refresh":"%s"}`, access, refresh), ttl)
        _ = kv.Set(r.Context(), "mfa:code:"+tx, code, ttl)
        // Enviar e-mail
        if mailer != nil {
            tmpl := cfg.SecurityTemplate
            if strings.TrimSpace(tmpl) == "" { tmpl = cfg.EmailTemplateName }
            data := map[string]any{
                "Title":   "Código de verificação (MFA)",
                "Message": "Use o código abaixo para concluir seu login.",
                "Email":   email,
                "Username": uname,
                "Code":    code,
                "Time":    time.Now().UTC().Format(time.RFC3339),
            }
            ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
            defer cancel()
            _ = mailer.Send(ctx, emailsvc.Params{To: []string{email}, Subject: "Seu código de MFA", TemplateName: tmpl, Data: data})
        }
        writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "mfa_required": true, "mfa_tx": tx})
        return
    }

    writeJSON(w, http.StatusOK, map[string]any{"success": true, "access_token": access, "refresh_token": refresh})
}

// adminAuthRefreshHandler é um stub do endpoint de refresh /admin/auth/token/refresh.
// Por enquanto retorna 501 (Not Implemented) até integração com sessões/refresh token.
func adminAuthRefreshHandler_old(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_002", "message": "refresh_token ausente"})
		return
	}
	access, refresh, err := service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		logWarn("refresh failed: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_002", "message": err.Error()})
		return
	}
	logInfo("refresh success")
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "access_token": access, "refresh_token": refresh})
}

// adminAuthMFAVerifyHandler valida o código de MFA enviado ao e-mail e retorna os tokens retidos.
func adminAuthMFAVerifyHandler_old(w http.ResponseWriter, r *http.Request) {
    var req struct{
        Tx   string `json:"mfa_tx"`
        Code string `json:"code"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Tx) == "" || strings.TrimSpace(req.Code) == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_MFA", "message": "JSON inválido"})
        return
    }
    // Tenta limitar tentativas por TX
    attemptsKey := "mfa:attempts:" + req.Tx
    if ok, n, _ := kv.AllowRate(r.Context(), attemptsKey, int64(cfg.MFAMaxAttempts), time.Duration(cfg.MFACodeTTLMinutes)*time.Minute); !ok {
        // estoura tentativas: limpa TX para segurança
        kv.Del(r.Context(), "mfa:tx:"+req.Tx, "mfa:code:"+req.Tx)
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_MFA", "message": "Muitas tentativas"})
        return
    } else { _ = n }
    stored, _ := kv.Get(r.Context(), "mfa:code:"+req.Tx)
    if strings.TrimSpace(stored) == "" || stored != strings.TrimSpace(req.Code) {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_MFA", "message": "Código inválido ou expirado"})
        return
    }
    data, _ := kv.Get(r.Context(), "mfa:tx:"+req.Tx)
    if strings.TrimSpace(data) == "" {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_MFA", "message": "Sessão MFA expirada"})
        return
    }
    // Limpa chaves
    kv.Del(r.Context(), "mfa:tx:"+req.Tx, "mfa:code:"+req.Tx, attemptsKey)
    // Retorna os tokens
    var resp map[string]any
    _ = json.Unmarshal([]byte(data), &resp)
    if resp == nil { resp = map[string]any{} }
    resp["success"] = true
    writeJSON(w, http.StatusOK, resp)
}

func generateNumericCode(n int) string { return generateNumericPassword(n) }

// ===== User Auth Handlers =====

// userAuthTokenHandler: POST /user/auth/token
// Autentica usuário por username/password e emite par de tokens.
func userAuthTokenHandler_old(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
        return
    }
    ip := clientIP(r)
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:userlogin:ip:"+ip, int64(cfg.LoginIPLimit), time.Duration(cfg.LoginIPWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_IP", "message": "Muitas tentativas. Tente mais tarde."})
        return
    }
    var req struct{ Username, Password string }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_001", "message": "JSON inválido"})
        return
    }
    username := strings.ToLower(strings.TrimSpace(req.Username))
    if locked, _ := kv.IsLocked(r.Context(), "lock:userlogin:"+username); locked {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_LOCK", "message": "Conta temporariamente bloqueada."})
        return
    }
    var (
        id int64
        email string
        passHash string
        toolsRole string
        plan string
        verified bool
        expiresAt sql.NullTime
    )
    err := sqldb.QueryRow(db.Rebind(`SELECT id, email, password_hash, tools_role, subscription_plan, expires_at, is_verified FROM users WHERE username = ? LIMIT 1`), username).
        Scan(&id, &email, &passHash, &toolsRole, &plan, &expiresAt, &verified)
    if err != nil || bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.Password)) != nil || !verified {
        if ok, n, _ := kv.AllowRate(r.Context(), "rl:userloginfail:"+username, int64(cfg.LoginFailLockThreshold), time.Duration(cfg.LoginFailLockTTLMinutes)*time.Minute); !ok || n >= int64(cfg.LoginFailLockThreshold) {
            _ = kv.SetLock(r.Context(), "lock:userlogin:"+username, time.Duration(cfg.LoginFailLockTTLMinutes)*time.Minute)
        }
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_001", "message": "Credenciais inválidas ou conta não verificada"})
        return
    }
    now := time.Now()
    if strings.ToLower(plan) != "lifetime" {
        if !expiresAt.Valid || !expiresAt.Time.After(now) {
            writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_PLAN", "message": "Plano expirado"})
            return
        }
    }
    // Emite tokens e cria sessão
    sessionID := uuid.NewString()
    familyID := uuid.NewString()
    accessExp := now.Add(timeSeconds(parseIntEnv("TOKEN_ACCESS_EXPIRE_SECONDS", 1800)))
    if strings.ToLower(plan) != "lifetime" && expiresAt.Valid && accessExp.After(expiresAt.Time) {
        accessExp = expiresAt.Time
    }
    if !accessExp.After(now) {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_PLAN", "message": "Plano expirado"})
        return
    }
    access, err := signUserAccessTokenWithExp(id, email, sessionID, accessExp)
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_SIGN", "message": "Falha ao assinar token"})
        return
    }
    // Gera refresh token opaco
    refresh, err := func() (string, error) { b := make([]byte, 32); if _, e := crand.Read(b); e != nil { return "", e }; return hex.EncodeToString(b), nil }()
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_REFRESH", "message": "Falha ao gerar refresh"}); return }
    // Persist refresh
    hash := sha256.Sum256([]byte(refresh))
    refreshExp := now.Add(timeSeconds(parseIntEnv("TOKEN_REFRESH_EXPIRE_SECONDS", 2592000)))
    if strings.ToLower(plan) != "lifetime" && expiresAt.Valid && refreshExp.After(expiresAt.Time) {
        refreshExp = expiresAt.Time
    }
    if _, err := sqldb.Exec(db.Rebind(`INSERT INTO users_sessions_local (user_id, session_id, family_id, refresh_token_hash, expires_at) VALUES (?,?,?,?,?)`), id, sessionID, familyID, hex.EncodeToString(hash[:]), refreshExp); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_SESSION", "message": "Falha ao criar sessão"})
        return
    }
    // sucesso
    kv.Del(r.Context(), "rl:userloginfail:"+username, "lock:userlogin:"+username)
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "access_token": access, "refresh_token": refresh})
}

// userAuthRefreshHandler: POST /user/auth/token/refresh
func userAuthRefreshHandler_old(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
        return
    }
    var req struct{ RefreshToken string `json:"refresh_token"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.RefreshToken) == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_002", "message": "refresh_token ausente"})
        return
    }
    hash := sha256.Sum256([]byte(req.RefreshToken))
    var (
        userID int64
        plan string
        email string
        expiresAt sql.NullTime
        familyID string
    )
    q := db.Rebind(`SELECT s.user_id, u.subscription_plan, u.email, u.expires_at, s.family_id FROM users_sessions_local s JOIN users u ON u.id = s.user_id WHERE s.refresh_token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP AND s.revoked_at IS NULL AND u.is_verified = TRUE LIMIT 1`)
    if err := sqldb.QueryRow(q, hex.EncodeToString(hash[:])).Scan(&userID, &plan, &email, &expiresAt, &familyID); err != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_002", "message": "Refresh inválido"})
        return
    }
    now := time.Now()
    if strings.ToLower(plan) != "lifetime" {
        if !expiresAt.Valid || !expiresAt.Time.After(now) {
            writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_PLAN", "message": "Plano expirado"})
            return
        }
    }
    // revoke old
    _, _ = sqldb.Exec(db.Rebind(`UPDATE users_sessions_local SET revoked_at = ?, revoked_reason = ? WHERE refresh_token_hash = ?`), now, "rotated", hex.EncodeToString(hash[:]))
    // issue new
    sessionID := uuid.NewString()
    accessExp := now.Add(timeSeconds(parseIntEnv("TOKEN_ACCESS_EXPIRE_SECONDS", 1800)))
    if strings.ToLower(plan) != "lifetime" && expiresAt.Valid && accessExp.After(expiresAt.Time) { accessExp = expiresAt.Time }
    if !accessExp.After(now) { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_PLAN", "message": "Plano expirado"}); return }
    access, err := signUserAccessTokenWithExp(userID, email, sessionID, accessExp)
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_SIGN", "message": "Falha ao assinar token"}); return }
    // new refresh
    b := make([]byte, 32); _, _ = crand.Read(b)
    newRefresh := hex.EncodeToString(b)
    newHash := sha256.Sum256([]byte(newRefresh))
    refreshExp := now.Add(timeSeconds(parseIntEnv("TOKEN_REFRESH_EXPIRE_SECONDS", 2592000)))
    if strings.ToLower(plan) != "lifetime" && expiresAt.Valid && refreshExp.After(expiresAt.Time) { refreshExp = expiresAt.Time }
    ins := db.Rebind(`INSERT INTO users_sessions_local (user_id, session_id, family_id, refresh_token_hash, expires_at) VALUES (?,?,?,?,?)`)
    if _, err := sqldb.Exec(ins, userID, sessionID, familyID, hex.EncodeToString(newHash[:]), refreshExp); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_SESSION", "message": "Falha ao criar sessão"})
        return
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "access_token": access, "refresh_token": newRefresh})
}

// userAuthVerifyHandler: POST /user/auth/verify (code + password)
func userAuthVerifyHandler_old(w http.ResponseWriter, r *http.Request) {
    var req struct{ Code, Password string }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_006", "message": "JSON inválido"})
        return
    }
    req.Code = strings.TrimSpace(req.Code)
    req.Password = strings.TrimSpace(req.Password)
    if len(req.Code) != contants.VerificationCodeLength || req.Password == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_007", "message": "Código ou senha ausentes/invalidos"})
        return
    }
    var (
        userID int64
        passHash string
        verified bool
        verifID int64
    )
    err := sqldb.QueryRow(db.Rebind(`SELECT u.id, u.password_hash, u.is_verified, v.id FROM users_verifications v JOIN users u ON u.id = v.user_id WHERE v.code = ? AND v.consumed_at IS NULL AND (v.expires_at IS NULL OR v.expires_at > CURRENT_TIMESTAMP) LIMIT 1`), req.Code).
        Scan(&userID, &passHash, &verified, &verifID)
    if err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_008", "message": "Código inválido ou expirado"})
        return
    }
    if bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.Password)) != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_004", "message": "Senha inválida"})
        return
    }
    // Conclui verificação
    tx, _ := sqldb.Begin()
    _, _ = tx.Exec(db.Rebind(`UPDATE users SET is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), true, userID)
    _, _ = tx.Exec(db.Rebind(`UPDATE users_verifications SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?`), verifID)
    _ = tx.Commit()
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "user_id": userID, "verified": true})
}

// userAuthVerifyLinkHandler: GET /user/auth/verify-link?login=&code=
func userAuthVerifyLinkHandler_old(w http.ResponseWriter, r *http.Request) {
    login := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("login")))
    code := strings.TrimSpace(r.URL.Query().Get("code"))
    if login == "" || len(code) != contants.VerificationCodeLength {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_011", "message": "Parâmetros inválidos"})
        return
    }
    var userID int64
    err := sqldb.QueryRow(db.Rebind(`SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1`), login, login).Scan(&userID)
    if err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_012", "message": "Usuário não encontrado"})
        return
    }
    res, _ := sqldb.Exec(db.Rebind(`UPDATE users_verifications SET consumed_at = CURRENT_TIMESTAMP WHERE user_id = ? AND code = ? AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`), userID, code)
    n, _ := res.RowsAffected()
    if n == 0 {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_013", "message": "Código inválido ou expirado"})
        return
    }
    _, _ = sqldb.Exec(db.Rebind(`UPDATE users SET is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), true, userID)
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "user_id": userID, "verified": true})
}

// userAuthPasswordRecoveryHandler: POST /user/auth/password-recovery
func userAuthPasswordRecoveryHandler_old(w http.ResponseWriter, r *http.Request) {
    ip := clientIP(r)
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:userrecovery:ip:"+ip, int64(cfg.RecoveryIPLimit), time.Duration(cfg.RecoveryIPWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_IP", "message": "Muitas solicitações. Tente mais tarde."})
        return
    }
    var req struct{ Email string `json:"email"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_009", "message": "JSON inválido"})
        return
    }
    req.Email = strings.TrimSpace(strings.ToLower(req.Email))
    if req.Email == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_010", "message": "E-mail é obrigatório"})
        return
    }
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:userrecovery:email:"+req.Email, int64(cfg.RecoveryEmailLimit), time.Duration(cfg.RecoveryEmailWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_EMAIL", "message": "Limite de recuperação excedido. Tente mais tarde."})
        return
    }
    var (
        userID int64
        username string
    )
    err := sqldb.QueryRow(db.Rebind(`SELECT id, username FROM users WHERE email = ? LIMIT 1`), req.Email).Scan(&userID, &username)
    if err == sql.ErrNoRows {
        writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
        return
    }
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_007", "message": "Falha ao consultar usuário"})
        return
    }
    // nova senha
    newPass := ""
    if passwordPolicyStrict() { newPass = generateStrongPassword(12) } else { newPass = generateNumericPassword(contants.DefaultGeneratedPasswordLength) }
    hash, _ := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
    code, cerr := generateVerificationCode(contants.VerificationCodeLength)
    if cerr != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_009", "message": "Falha ao gerar código de verificação"}); return }
    tx, _ := sqldb.Begin()
    _, _ = tx.Exec(db.Rebind(`UPDATE users SET password_hash = ?, is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), string(hash), false, userID)
    _, _ = tx.Exec(db.Rebind(`INSERT INTO users_verifications (user_id, code, expires_at) VALUES (?,?,?)`), userID, code, time.Now().Add(time.Duration(cfg.VerifyCodeTTLHours)*time.Hour))
    _ = tx.Commit()
    // email
    if mailer != nil {
        data := map[string]any{ "Title": "Recuperação de senha", "Message": "Use a nova senha e o código para verificar sua conta.", "Email": req.Email, "Username": username, "Password": newPass, "VerificationCode": code }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second); defer cancel()
        _ = mailer.Send(ctx, emailsvc.Params{To: []string{req.Email}, Subject: contants.EmailSubjectPasswordRecovery, TemplateName: cfg.EmailTemplateName, Data: data})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

// userAuthVerificationCodeHandler: POST /user/auth/verification-code (reenvio)
func userAuthVerificationCodeHandler_old(w http.ResponseWriter, r *http.Request) {
    var req struct{ Login string `json:"login"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Login) == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_014", "message": "login ausente"})
        return
    }
    login := strings.ToLower(strings.TrimSpace(req.Login))
    var (
        userID int64
        email string
        username string
        verified bool
    )
    err := sqldb.QueryRow(db.Rebind(`SELECT id, email, username, is_verified FROM users WHERE username = ? OR email = ? LIMIT 1`), login, login).Scan(&userID, &email, &username, &verified)
    if err != nil { writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true}); return }
    if verified { writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true}); return }
    code, _ := generateVerificationCode(contants.VerificationCodeLength)
    _, _ = sqldb.Exec(db.Rebind(`INSERT INTO users_verifications (user_id, code, expires_at) VALUES (?,?,?)`), userID, code, time.Now().Add(time.Duration(cfg.VerifyCodeTTLHours)*time.Hour))
    if mailer != nil {
        data := map[string]any{ "Title": "Verificação de conta", "Message": "Seu código de verificação:", "Email": email, "Username": username, "VerificationCode": code }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second); defer cancel()
        _ = mailer.Send(ctx, emailsvc.Params{To: []string{email}, Subject: contants.EmailSubjectUserCreated, TemplateName: cfg.EmailTemplateName, Data: data})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

// ===== UsersSpaces Handlers =====

// userSpacesCreateHandler: POST /user/spaces (somente usuário com tools_role=admin)
func userSpacesCreateHandler_old(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
        return
    }
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    var role string
    if err := sqldb.QueryRow(db.Rebind(`SELECT tools_role FROM users WHERE id = ?`), userID).Scan(&role); err != nil || strings.ToLower(role) != "admin" {
        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_SPACE", "message": "Permissão insuficiente"})
        return
    }
    var req struct{ Name string `json:"name"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_SPACE", "message": "Nome é obrigatório"})
        return
    }
    // Gera hash único
    hash := generateUsersSpaceHash(contants.UsersSpaceHashLength)
    q := db.Rebind(`INSERT INTO users_spaces (owner_user_id, name, hash) VALUES (?,?,?)`)
    res, err := sqldb.Exec(q, userID, strings.TrimSpace(req.Name), hash)
    if err != nil { writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_SPACE", "message": "Conflito ao criar"}); return }
    newID, _ := res.LastInsertId()
    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": newID, "name": req.Name, "hash": hash})
}

// userSpacesListHandler: GET /user/spaces (lista espaços onde o usuário é owner)
func userSpacesListHandler_old(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
        return
    }
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    rows, err := sqldb.Query(db.Rebind(`SELECT id, name, hash, created_at, updated_at FROM users_spaces WHERE owner_user_id = ? ORDER BY id DESC`), userID)
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_SPACE", "message": "Falha ao listar"}); return }
    defer rows.Close()
    list := make([]map[string]any, 0)
    for rows.Next() {
        var id int64; var name, hash string; var createdAt, updatedAt time.Time
        _ = rows.Scan(&id, &name, &hash, &createdAt, &updatedAt)
        list = append(list, map[string]any{"id": id, "name": name, "hash": hash, "created_at": createdAt, "updated_at": updatedAt})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": list})
}

// signUserAccessTokenWithExp cria JWT de usuário com claims pedidas: uid, email, user=true
// moved to users_handlers.go; keep stub to avoid breakage if referenced
func signUserAccessTokenWithExpOld(userID int64, email, sessionID string, exp time.Time) (string, error) {
    claims := jwt.MapClaims{
        "sub":  fmt.Sprintf("user|%d", userID),
        "uid":  userID,
        "email": email,
        "user": true,
        "sid":  sessionID,
        "exp":  exp.Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(cfg.SecretKey))
}

// ===== UsersSpaces Members Handlers =====

func isValidMemberRole_old(role string) bool {
    switch strings.ToLower(strings.TrimSpace(role)) {
    case "admin", "user", "guest":
        return true
    }
    return false
}

// userSpacesMembersAddHandler: POST /user/spaces/{space_id}/members
func userSpacesMembersAddHandler_old(w http.ResponseWriter, r *http.Request) {
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 4 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    spaceID, e := strconv.ParseInt(parts[2], 10, 64)
    if e != nil || spaceID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_SPACE_ID"}); return }
    // verifica ownership
    var ownerID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT owner_user_id FROM users_spaces WHERE id = ? LIMIT 1`), spaceID).Scan(&ownerID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_SPACE"}); return }
    if ownerID != userID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_SPACE", "message": "Apenas o proprietário pode gerenciar membros"}); return }
    var req struct{ Login string `json:"login"`; Role string `json:"role"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Login) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_MEMBER", "message": "login/role inválidos"}); return }
    role := strings.ToLower(strings.TrimSpace(req.Role))
    if role == "" { role = "guest" }
    if !isValidMemberRole(role) { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_ROLE"}); return }
    // resolve user alvo
    login := strings.ToLower(strings.TrimSpace(req.Login))
    var targetID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1`), login, login).Scan(&targetID); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_USER_NOT_FOUND"}); return }
    if targetID == ownerID { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_OWNER", "message": "Proprietário não é membro gerenciável"}); return }
    // insere membership
    res, err := sqldb.Exec(db.Rebind(`INSERT INTO users_spaces_members (space_id, user_id, role) VALUES (?,?,?)`), spaceID, targetID, role)
    if err != nil { writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_MEMBER"}); return }
    mid, _ := res.LastInsertId()
    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "member_id": mid, "space_id": spaceID, "user_id": targetID, "role": role})
}

// userSpacesMembersListHandler: GET /user/spaces/{space_id}/members
func userSpacesMembersListHandler_old(w http.ResponseWriter, r *http.Request) {
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 4 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    spaceID, e := strconv.ParseInt(parts[2], 10, 64)
    if e != nil || spaceID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_SPACE_ID"}); return }
    var ownerID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT owner_user_id FROM users_spaces WHERE id = ? LIMIT 1`), spaceID).Scan(&ownerID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_SPACE"}); return }
    if ownerID != userID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_SPACE"}); return }
    rows, err := sqldb.Query(db.Rebind(`
        SELECT m.user_id, u.username, u.email, m.role, m.created_at, m.updated_at
        FROM users_spaces_members m
        JOIN users u ON u.id = m.user_id
        WHERE m.space_id = ? ORDER BY m.user_id ASC`), spaceID)
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_MEMBERS"}); return }
    defer rows.Close()
    list := make([]map[string]any, 0)
    for rows.Next() {
        var uid int64; var uname, email, role string; var cAt, uAt time.Time
        _ = rows.Scan(&uid, &uname, &email, &role, &cAt, &uAt)
        list = append(list, map[string]any{"user_id": uid, "username": uname, "email": email, "role": role, "created_at": cAt, "updated_at": uAt})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": list})
}

// userSpacesMembersUpdateRoleHandler: PATCH /user/spaces/{space_id}/members/{user_id}
func userSpacesMembersUpdateRoleHandler_old(w http.ResponseWriter, r *http.Request) {
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 5 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    spaceID, e1 := strconv.ParseInt(parts[2], 10, 64)
    targetID, e2 := strconv.ParseInt(parts[4], 10, 64)
    if e1 != nil || e2 != nil || spaceID <= 0 || targetID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_IDS"}); return }
    var ownerID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT owner_user_id FROM users_spaces WHERE id = ? LIMIT 1`), spaceID).Scan(&ownerID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_SPACE"}); return }
    if ownerID != userID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_SPACE"}); return }
    if targetID == ownerID { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_OWNER"}); return }
    var req struct{ Role string `json:"role"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_JSON"}); return }
    role := strings.ToLower(strings.TrimSpace(req.Role))
    if !isValidMemberRole(role) { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_ROLE"}); return }
    res, err := sqldb.Exec(db.Rebind(`UPDATE users_spaces_members SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE space_id = ? AND user_id = ?`), role, spaceID, targetID)
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_MEMBER_UPD"}); return }
    n, _ := res.RowsAffected(); if n == 0 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_MEMBER"}); return }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "user_id": targetID, "role": role})
}

// userSpacesMembersRemoveHandler: DELETE /user/spaces/{space_id}/members/{user_id}
func userSpacesMembersRemoveHandler_old(w http.ResponseWriter, r *http.Request) {
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 5 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    spaceID, e1 := strconv.ParseInt(parts[2], 10, 64)
    targetID, e2 := strconv.ParseInt(parts[4], 10, 64)
    if e1 != nil || e2 != nil || spaceID <= 0 || targetID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_IDS"}); return }
    var ownerID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT owner_user_id FROM users_spaces WHERE id = ? LIMIT 1`), spaceID).Scan(&ownerID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_SPACE"}); return }
    if ownerID != userID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_SPACE"}); return }
    if targetID == ownerID { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_OWNER"}); return }
    res, err := sqldb.Exec(db.Rebind(`DELETE FROM users_spaces_members WHERE space_id = ? AND user_id = ?`), spaceID, targetID)
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_MEMBER_DEL"}); return }
    n, _ := res.RowsAffected(); if n == 0 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_MEMBER"}); return }
    writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// adminAuthPasswordRecoveryHandler permite a recuperação de senha sem autenticação.
// Recebe um e-mail, gera uma nova senha e um novo código de verificação e os envia por e-mail.
func adminAuthPasswordRecoveryHandler_old(w http.ResponseWriter, r *http.Request) {
    // Throttle por IP e por e-mail
    ip := clientIP(r)
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:recovery:ip:"+ip, int64(cfg.RecoveryIPLimit), time.Duration(cfg.RecoveryIPWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_IP", "message": "Muitas solicitações. Tente mais tarde."})
        return
    }
    var req struct {
        Email string `json:"email"`
    }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_009", "message": "JSON inválido"})
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_010", "message": "E-mail é obrigatório"})
		return
	}
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:recovery:email:"+req.Email, int64(cfg.RecoveryEmailLimit), time.Duration(cfg.RecoveryEmailWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_EMAIL", "message": "Limite de recuperação excedido. Tente mais tarde."})
        return
    }

	// Busca admin por e-mail. Em caso de não encontrado, retornamos sucesso para evitar enumeração.
	var (
		adminID  int64
		username string
	)
	err := sqldb.QueryRow(db.Rebind(`SELECT id, username FROM admins WHERE email = ? LIMIT 1`), req.Email).Scan(&adminID, &username)
	if err == sql.ErrNoRows {
		// Resposta genérica para não expor existência.
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_007", "message": "Falha ao consultar usuário"})
		return
	}

	// Gera nova senha conforme política e atualiza hash
	newPass := ""
	if passwordPolicyStrict() {
		newPass = generateStrongPassword(12)
	} else {
		newPass = generateNumericPassword(contants.DefaultGeneratedPasswordLength)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_008", "message": "Falha ao processar senha"})
		return
	}

	// Gera novo código de verificação
	code, err := generateVerificationCode(contants.VerificationCodeLength)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_009", "message": "Falha ao gerar código de verificação"})
		return
	}

	// Atualiza senha e marca conta como não verificada; insere novo código
	tx, err := sqldb.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_010", "message": "Falha ao iniciar transação"})
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(db.Rebind(`UPDATE admins SET password_hash = ?, is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), string(hash), false, adminID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_011", "message": "Falha ao atualizar senha"})
		return
	}
    if _, err := tx.Exec(db.Rebind(`INSERT INTO admins_verifications (admin_id, code, expires_at) VALUES (?, ?, ?)`), adminID, code, time.Now().Add(24*time.Hour)); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_012", "message": "Falha ao criar código de verificação"})
        return
    }
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_013", "message": "Falha ao confirmar recuperação"})
		return
	}

    // Envia e-mail com nova senha e código.
    // Em serverless (Vercel), evite goroutine: envie de forma síncrona antes de responder.
    if mailer != nil {
        verifyURL := buildVerifyURL(r, code)
        tmpl := cfg.AdminCreatedTemplate
        if strings.TrimSpace(tmpl) == "" {
            tmpl = cfg.EmailTemplateName
        }
        data := map[string]any{
            "Title":            "Recuperação de senha",
            "Message":          "Sua senha foi redefinida. Use a nova senha e o código abaixo para verificar sua conta.",
            "Email":            req.Email,
            "Username":         username,
            "Password":         newPass,
            "VerificationCode": code,
            "VerifyURL":        verifyURL,
        }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
        defer cancel()
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            if err := mailer.Send(ctx, emailsvc.Params{
                To:           []string{req.Email},
                Subject:      contants.EmailSubjectPasswordRecovery,
                TemplateName: tmpl,
                Data:         data,
            }); err != nil {
                writeJSON(w, http.StatusBadGateway, map[string]any{"success": false, "code": "EMAIL_502_SEND", "message": "Falha ao enviar e-mail"})
                return
            }
        } else {
            go func(p emailsvc.Params) {
                if err := mailer.Send(ctx, p); err != nil {
                    logWarn("send email password recovery: %v", err)
                }
            }(emailsvc.Params{To: []string{req.Email}, Subject: contants.EmailSubjectPasswordRecovery, TemplateName: tmpl, Data: data})
        }
    }

	writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

// adminListHandler lista administradores conforme privilégio do solicitante.
// Regra: pode ver apenas papéis com prioridade inferior ao seu.
// Exceção: root vê todos, inclusive outros root.
func adminListHandler_old(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
		return
	}
	_, actingRole, err := authenticateAdmin(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_005", "message": err.Error()})
		return
	}
	// Paginação via query params: offset (>=0), limit (1..100)
	q := r.URL.Query()
	offset := 0
	limit := 20
	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n >= 0 {
			offset = n
		}
	}
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			if n < 1 {
				n = 1
			}
			if n > 100 {
				n = 100
			}
			limit = n
		}
	}
	role := strings.ToLower(strings.TrimSpace(actingRole))
	// Map de prioridade
	prio := map[string]int{"guest": 0, "user": 1, "admin": 2, "root": 3}
	actingPrio := prio[role]

	// Se root: lista todos
	var rows *sql.Rows
	if role == "root" {
		rows, err = sqldb.Query(db.Rebind(`SELECT id, email, username, system_role, is_verified FROM admins ORDER BY id ASC LIMIT ? OFFSET ?`), limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_014", "message": "Falha ao consultar administradores"})
			return
		}
		defer rows.Close()
	} else {
		// Determina papéis permitidos (estritamente menores)
		allowed := make([]string, 0, 4)
		for k, v := range prio {
			if v < actingPrio {
				allowed = append(allowed, k)
			}
		}
		if len(allowed) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "offset": offset, "limit": limit, "items": []any{}})
			return
		}
		// Monta placeholders e args
		ph := make([]string, len(allowed))
		args := make([]any, len(allowed))
		for i, r := range allowed {
			ph[i] = "?"
			args[i] = r
		}
		query := `SELECT id, email, username, system_role, is_verified FROM admins WHERE LOWER(system_role) IN (` + strings.Join(ph, ",") + `) ORDER BY id ASC LIMIT ? OFFSET ?`
		args = append(args, limit, offset)
		rows, err = sqldb.Query(db.Rebind(query), args...)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_015", "message": "Falha ao consultar administradores"})
			return
		}
		defer rows.Close()
	}

	type item struct {
		ID         int64  `json:"id"`
		Email      string `json:"email"`
		Username   string `json:"username"`
		SystemRole string `json:"system_role"`
		IsVerified bool   `json:"is_verified"`
	}
	var list []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.Email, &it.Username, &it.SystemRole, &it.IsVerified); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_016", "message": "Falha ao ler resultado"})
			return
		}
		list = append(list, it)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_017", "message": "Falha ao ler resultado"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "offset": offset, "limit": limit, "items": list})
}

// adminCreateHandler cria um novo administrador. Requer autenticação Bearer e papel suficiente.
func adminCreateHandler_old(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
		return
	}
	actingID, actingRole, err := authenticateAdmin(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_003", "message": err.Error()})
		return
	}
    var req struct {
        Email            string `json:"email"`
        Username         string `json:"username"`
        Password         string `json:"password"`
        SystemRole       string `json:"system_role"`
        SubscriptionPlan string `json:"subscription_plan"`
    }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_003", "message": "JSON inválido"})
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	req.SystemRole = strings.TrimSpace(req.SystemRole)
	if req.Email == "" || req.Username == "" || req.SystemRole == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_004", "message": "Campos obrigatórios ausentes"})
		return
	}
	// Política de senha: se vazia, gera automática; se informada, valida.
	req.Password = strings.TrimSpace(req.Password)
	if req.Password == "" {
		if passwordPolicyStrict() {
			req.Password = generateStrongPassword(12)
		} else {
			req.Password = generateNumericPassword(contants.DefaultGeneratedPasswordLength)
		}
	} else {
		if err := validatePassword(req.Password); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_005", "message": err.Error()})
			return
		}
	}
    if !canManageSystemRole(actingRole, req.SystemRole) {
        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_001", "message": "Papel insuficiente para criar este administrador"})
        return
    }
    // Plano de assinatura
    plan := strings.ToLower(strings.TrimSpace(req.SubscriptionPlan))
    if plan == "" { plan = "monthly" }
    if !isValidPlan(plan) {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_021", "message": "subscription_plan inválido"})
        return
    }
    // Somente root pode conceder planos acima de semiannual
    if strings.ToLower(actingRole) != "root" && !canGrantPlan(plan) {
        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_011", "message": "Papel insuficiente para conceder este plano"})
        return
    }
    var expires any = nil
    if plan != "lifetime" {
        e := computeExpires(plan, time.Now())
        expires = e
    }
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_001", "message": "Falha ao processar senha"})
		return
	}
	// Inserção no banco
	var ownerID any = nil
	if actingID > 0 {
		ownerID = actingID
	}
	var newID int64
    if db.IsPostgres() {
        // Postgres requer RETURNING para obter o id
        q := db.Rebind(`INSERT INTO admins (email, username, password_hash, system_role, subscription_plan, expires_at, is_verified, owner_id) VALUES (?,?,?,?,?,?,?,?) RETURNING id`)
        if err := sqldb.QueryRow(q, req.Email, req.Username, string(hash), req.SystemRole, plan, expires, false, ownerID).Scan(&newID); err != nil {
            writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_001", "message": "Email ou username já existente"})
            return
        }
    } else {
        res, err := sqldb.Exec(db.Rebind(`INSERT INTO admins (email, username, password_hash, system_role, subscription_plan, expires_at, is_verified, owner_id) VALUES (?,?,?,?,?,?,?,?)`), req.Email, req.Username, string(hash), req.SystemRole, plan, expires, false, ownerID)
        if err != nil {
            writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_001", "message": "Email ou username já existente"})
            return
        }
        newID, _ = res.LastInsertId()
    }

    // Gera código de verificação único e persiste
    code, err := generateVerificationCode(contants.VerificationCodeLength)
    if err == nil {
        exp := time.Now().Add(24 * time.Hour)
        if _, e := sqldb.Exec(db.Rebind(`INSERT INTO admins_verifications (admin_id, code, expires_at) VALUES (?,?,?)`), newID, code, exp); e != nil {
            logWarn("save verification code failed: %v", e)
        }
    } else {
        logWarn("generate verification code failed: %v", err)
        code = ""
    }

    // Envia e-mail de criação (síncrono em serverless, assíncrono em servidor local).
    if mailer != nil {
        tmpl := cfg.EmailTemplateName
        if cfg.AdminCreatedTemplate != "" {
            tmpl = cfg.AdminCreatedTemplate
        }
        verifyURL := buildVerifyURL(r, code)
        data := map[string]any{
            "Title":            "Conta de administrador criada",
            "Message":          "Sua conta foi criada com sucesso.",
            "Email":            req.Email,
            "Username":         req.Username,
            "SystemRole":       req.SystemRole,
            "CreatedByRole":    actingRole,
            "Password":         req.Password,
            "VerificationCode": code,
            "VerifyURL":        verifyURL,
        }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
        defer cancel()
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            if err := mailer.Send(ctx, emailsvc.Params{To: []string{req.Email}, Subject: contants.EmailSubjectAdminCreated, TemplateName: tmpl, Data: data}); err != nil {
                logWarn("send email admin created: %v", err)
            }
        } else {
            go func(p emailsvc.Params) {
                if err := mailer.Send(ctx, p); err != nil {
                    logWarn("send email admin created: %v", err)
                }
            }(emailsvc.Params{To: []string{req.Email}, Subject: contants.EmailSubjectAdminCreated, TemplateName: tmpl, Data: data})
        }
    }

	writeJSON(w, http.StatusCreated, map[string]any{
		"success":     true,
		"admin_id":    newID,
		"username":    req.Username,
		"email":       req.Email,
        "system_role": req.SystemRole,
        "subscription_plan": plan,
        "expires_at": expires,
    })
}

// Subscription plan helpers
func isValidPlan(plan string) bool {
    switch strings.ToLower(plan) {
    case "minute", "hourly", "daily", "trial", "monthly", "semiannual", "annual", "lifetime":
        return true
    }
    return false
}

// Non-root can only grant up to semiannual (inclusive)
func canGrantPlan(plan string) bool {
    allowed := map[string]bool{"minute": true, "hourly": true, "daily": true, "trial": true, "monthly": true, "semiannual": true}
    return allowed[strings.ToLower(plan)]
}

func computeExpires(plan string, now time.Time) time.Time {
    switch strings.ToLower(strings.TrimSpace(plan)) {
    case "annual":
        return now.AddDate(1, 0, 0)
    case "semiannual":
        return now.AddDate(0, 6, 0)
    case "monthly":
        return now.AddDate(0, 1, 0)
    case "trial":
        return now.AddDate(0, 0, 7)
    case "daily":
        return now.AddDate(0, 0, 1)
    case "hourly":
        return now.Add(time.Hour)
    case "minute":
        return now.Add(5 * time.Minute)
    default:
        return now
    }
}

// adminAuthVerifyHandler confirma a conta de admin a partir de um código e senha.
// Rota pública (sem Bearer), pois admin ainda não está ativo.
func adminAuthVerifyHandler_old(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_006", "message": "JSON inválido"})
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	req.Password = strings.TrimSpace(req.Password)
	if len(req.Code) != contants.VerificationCodeLength || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_007", "message": "Código ou senha ausentes/invalidos"})
		return
	}

	// Busca admin e registro de verificação válido (não consumido)
	var (
		adminID    int64
		passHash   string
		isVerified bool
		verifID    int64
	)
    err := sqldb.QueryRow(db.Rebind(`
        SELECT a.id, a.password_hash, a.is_verified, v.id
        FROM admins_verifications v
        JOIN admins a ON a.id = v.admin_id
        WHERE v.code = ? AND v.consumed_at IS NULL AND (v.expires_at IS NULL OR v.expires_at > CURRENT_TIMESTAMP)
        LIMIT 1
    `), req.Code).Scan(&adminID, &passHash, &isVerified, &verifID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_008", "message": "Código inválido ou expirado"})
		return
	}
	// Senha deve corresponder à senha inicial já cadastrada
	if bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_004", "message": "Senha inválida"})
		return
	}
	// Marca verificado e consome o código
	tx, err := sqldb.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_003", "message": "Falha ao iniciar transação"})
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(db.Rebind(`UPDATE admins SET is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), true, adminID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_004", "message": "Falha ao atualizar verificação"})
		return
	}
	if _, err := tx.Exec(db.Rebind(`UPDATE admins_verifications SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?`), verifID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_005", "message": "Falha ao consumir código"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_006", "message": "Falha ao confirmar verificação"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "verified": true})
}

// adminUpdateSubscriptionPlanHandler atualiza o subscription_plan do admin alvo, respeitando hierarquia e limites.
func adminUpdateSubscriptionPlanHandler_old(w http.ResponseWriter, r *http.Request) {
    // URL esperada: /admin/{id}/subscription-plan
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 3 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    idStr := parts[1]
    targetID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil || targetID <= 0 {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_022", "message": "admin_id inválido"})
        return
    }
    _, actingRole, err := authenticateAdmin(r)
    if err != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_005", "message": err.Error()})
        return
    }
    var req struct{ SubscriptionPlan string `json:"subscription_plan"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.SubscriptionPlan) == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_021", "message": "subscription_plan inválido"})
        return
    }
    newPlan := strings.ToLower(strings.TrimSpace(req.SubscriptionPlan))
    if !isValidPlan(newPlan) {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_021", "message": "subscription_plan inválido"})
        return
    }
    // Busca target para conferir hierarquia e papel
    var targetRole string
    err = sqldb.QueryRow(db.Rebind(`SELECT system_role FROM admins WHERE id = ? LIMIT 1`), targetID).Scan(&targetRole)
    if err == sql.ErrNoRows {
        writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_002", "message": "Admin não encontrado"})
        return
    }
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_020", "message": "Falha ao buscar admin"})
        return
    }
    // Hierarquia: somente alterar inferiores; root pode todos
    if strings.ToLower(actingRole) != "root" {
        if !canManageSystemRole(actingRole, targetRole) {
            writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_010", "message": "Papel insuficiente para alterar este administrador"})
            return
        }
        if !canGrantPlan(newPlan) {
            writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_011", "message": "Papel insuficiente para conceder este plano"})
            return
        }
    }
    var expires any = nil
    if newPlan != "lifetime" {
        e := computeExpires(newPlan, time.Now())
        expires = e
    }
    if _, err := sqldb.Exec(db.Rebind(`UPDATE admins SET subscription_plan = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), newPlan, expires, targetID); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_021", "message": "Falha ao atualizar plano"})
        return
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "admin_id": targetID, "new_plan": newPlan})
}

// adminUpdateSystemRoleHandler atualiza o system_role do admin alvo respeitando hierarquia.
func adminUpdateSystemRoleHandler_old(w http.ResponseWriter, r *http.Request) {
    // URL esperada: /admin/{id}/system-role
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 3 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    idStr := parts[1]
    targetID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil || targetID <= 0 {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_023", "message": "admin_id inválido"})
        return
    }
    _, actingRole, err := authenticateAdmin(r)
    if err != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_005", "message": err.Error()})
        return
    }
    var req struct{ SystemRole string `json:"system_role"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_024", "message": "JSON inválido"})
        return
    }
    newRole := strings.ToLower(strings.TrimSpace(req.SystemRole))
    if !isValidSystemRole(newRole) {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_025", "message": "system_role inválido"})
        return
    }
    var oldRole string
    if err := sqldb.QueryRow(db.Rebind(`SELECT system_role FROM admins WHERE id = ? LIMIT 1`), targetID).Scan(&oldRole); err != nil {
        if err == sql.ErrNoRows {
            writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_002", "message": "Admin não encontrado"})
            return
        }
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_022", "message": "Falha ao carregar admin"})
        return
    }

    // Regras de hierarquia: acting deve ser estritamente superior ao alvo e ao novo papel (exceto root, que pode todos)
    if strings.ToLower(actingRole) != "root" {
        if !canManageSystemRole(actingRole, oldRole) {
            writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_010", "message": "Papel insuficiente para alterar este administrador"})
            return
        }
        if !canManageSystemRole(actingRole, newRole) {
            writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_012", "message": "Papel insuficiente para definir o novo system_role"})
            return
        }
    }

    if _, err := sqldb.Exec(db.Rebind(`UPDATE admins SET system_role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), newRole, targetID); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_023", "message": "Falha ao atualizar system_role"})
        return
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "admin_id": targetID, "old_role": oldRole, "new_role": newRole})
}

func isValidSystemRole(role string) bool {
    switch strings.ToLower(strings.TrimSpace(role)) {
    case "guest", "user", "admin", "root":
        return true
    }
    return false
}

// adminChangeOwnPasswordHandler permite ao admin autenticado alterar sua própria senha.
// Requer o password atual e o novo; aplica a política de senha (modo estrito opcional).
func adminChangeOwnPasswordHandler_old(w http.ResponseWriter, r *http.Request) {
    actingID, _, err := authenticateAdmin(r)
    if err != nil || actingID <= 0 {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_005", "message": "não autorizado"})
        return
    }
    var req struct{
        CurrentPassword string `json:"current_password"`
        NewPassword     string `json:"new_password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_030", "message": "JSON inválido"})
        return
    }
    req.CurrentPassword = strings.TrimSpace(req.CurrentPassword)
    req.NewPassword = strings.TrimSpace(req.NewPassword)
    if req.CurrentPassword == "" || req.NewPassword == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_031", "message": "Campos obrigatórios ausentes"})
        return
    }
    if err := validatePassword(req.NewPassword); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_005", "message": err.Error()})
        return
    }
    var (
        email string
        username string
        passHash string
    )
    if err := sqldb.QueryRow(db.Rebind(`SELECT email, username, password_hash FROM admins WHERE id = ? LIMIT 1`), actingID).Scan(&email, &username, &passHash); err != nil {
        writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_001", "message": "Administrador não encontrado"})
        return
    }
    if bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.CurrentPassword)) != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_006", "message": "Senha atual inválida"})
        return
    }
    newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_030", "message": "Falha ao processar nova senha"})
        return
    }
    if _, err := sqldb.Exec(db.Rebind(`UPDATE admins SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), string(newHash), actingID); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_031", "message": "Falha ao atualizar senha"})
        return
    }
    // E-mail de confirmação (melhor esforço)
    if mailer != nil {
        tmpl := cfg.SecurityTemplate
        if strings.TrimSpace(tmpl) == "" { tmpl = cfg.EmailTemplateName }
        data := map[string]any{
            "Title":   "Senha alterada",
            "Message": "Sua senha foi alterada com sucesso.",
            "Event":   "password_changed",
            "Email":   email,
            "Username": username,
            "Time":    time.Now().UTC().Format(time.RFC3339),
        }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
        defer cancel()
        params := emailsvc.Params{To: []string{email}, Subject: "Confirmação de alteração de senha", TemplateName: tmpl, Data: data}
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            _ = mailer.Send(ctx, params)
        } else {
            go func() { _ = mailer.Send(ctx, params) }()
        }
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// adminCreateAPITokenHandler cria um token de API (PAT) para uso via Bearer (integrações como n8n),
// com as mesmas permissões do administrador autenticado.
// Entrada: { name?: string, ttl_hours?: int, expires_at?: RFC3339 }
// Saída: { success: true, token: string, token_id: number, name?: string, expires_at?: time }
func adminCreateAPITokenHandler_old(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
        return
    }
    actingID, _, err := authenticateAdmin(r)
    if err != nil || actingID <= 0 {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_PAT", "message": "não autorizado"})
        return
    }
    var req struct {
        Name      string `json:"name"`
        TTLHours  int    `json:"ttl_hours"`
        ExpiresAt string `json:"expires_at"` // RFC3339 opcional
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_PAT", "message": "JSON inválido"})
        return
    }
    name := strings.TrimSpace(req.Name)
    if len(name) > 128 { name = name[:128] }
    // Calcula expiração: default segue TOKEN_REFRESH_EXPIRE_SECONDS; sempre clamp por admins.expires_at (quando aplicável)
    now := time.Now()
    var exp time.Time
    if strings.TrimSpace(req.ExpiresAt) != "" {
        t, e := time.Parse(time.RFC3339, req.ExpiresAt)
        if e != nil {
            writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_EXP", "message": "expires_at inválido (RFC3339)"})
            return
        }
        exp = t
    } else if req.TTLHours > 0 {
        exp = now.Add(time.Duration(req.TTLHours) * time.Hour)
    } else {
        // Default ao mesmo TTL do refresh token
        refreshSec := parseIntEnv("TOKEN_REFRESH_EXPIRE_SECONDS", 2592000)
        exp = now.Add(timeSeconds(refreshSec))
    }
    // Clamp conforme plano/expiração do admin
    var plan string
    var adminExpires sql.NullTime
    if err := sqldb.QueryRow(db.Rebind(`SELECT subscription_plan, expires_at FROM admins WHERE id = ? LIMIT 1`), actingID).Scan(&plan, &adminExpires); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_PAT_ADMIN", "message": "Falha ao validar conta"})
        return
    }
    if strings.ToLower(plan) != "lifetime" && adminExpires.Valid {
        if exp.After(adminExpires.Time) {
            exp = adminExpires.Time
        }
    }
    if !exp.After(now) {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_EXP_RANGE", "message": "expiração deve ser futura"})
        return
    }
    // Gera token opaco e salva hash
    tokBytes := make([]byte, 32)
    if _, err := crand.Read(tokBytes); err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_PAT", "message": "Falha ao gerar token"})
        return
    }
    token := hex.EncodeToString(tokBytes)
    h := sha256.Sum256([]byte(token))
    var id int64
    if db.IsPostgres() {
        q := db.Rebind(`INSERT INTO admins_api_tokens (admin_id, name, token_hash, expires_at) VALUES (?,?,?,?) RETURNING id`)
        if err := sqldb.QueryRow(q, actingID, name, hex.EncodeToString(h[:]), exp).Scan(&id); err != nil {
            writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_PAT_INS", "message": "Falha ao salvar token"})
            return
        }
    } else {
        res, err := sqldb.Exec(db.Rebind(`INSERT INTO admins_api_tokens (admin_id, name, token_hash, expires_at) VALUES (?,?,?,?)`), actingID, name, hex.EncodeToString(h[:]), exp)
        if err != nil {
            writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_PAT_INS", "message": "Falha ao salvar token"})
            return
        }
        id, _ = res.LastInsertId()
    }
    // Retorna o token em claro apenas uma vez
    writeJSON(w, http.StatusCreated, map[string]any{
        "success":   true,
        "token_id":  id,
        "token":     token,
        "name":      name,
        "expires_at": exp,
    })
}

// adminAuthVerifyCodeURLHandler confirma a conta recebendo o código na URL e senha no corpo.
func adminAuthVerifyCodeURLHandler_old(w http.ResponseWriter, r *http.Request, code string) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_006", "message": "JSON inválido"})
		return
	}
	code = strings.TrimSpace(code)
	req.Password = strings.TrimSpace(req.Password)
	if len(code) != contants.VerificationCodeLength || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_007", "message": "Código ou senha ausentes/invalidos"})
		return
	}

	var (
		adminID    int64
		passHash   string
		isVerified bool
		verifID    int64
	)
    err := sqldb.QueryRow(db.Rebind(`
        SELECT a.id, a.password_hash, a.is_verified, v.id
        FROM admins_verifications v
        JOIN admins a ON a.id = v.admin_id
        WHERE v.code = ? AND v.consumed_at IS NULL AND (v.expires_at IS NULL OR v.expires_at > CURRENT_TIMESTAMP)
        LIMIT 1
    `), code).Scan(&adminID, &passHash, &isVerified, &verifID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_008", "message": "Código inválido ou expirado"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(passHash), []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_004", "message": "Senha inválida"})
		return
	}
	tx, err := sqldb.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_003", "message": "Falha ao iniciar transação"})
		return
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(db.Rebind(`UPDATE admins SET is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), true, adminID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_004", "message": "Falha ao atualizar verificação"})
		return
	}
	if _, err := tx.Exec(db.Rebind(`UPDATE admins_verifications SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?`), verifID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_005", "message": "Falha ao consumir código"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_006", "message": "Falha ao confirmar verificação"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "verified": true})
}

// Handler é o ponto de entrada exigido pelo runtime Go da Vercel.
// Ele roteia as requisições por caminho e método, delegando para handlers específicos.
func Handler(w http.ResponseWriter, r *http.Request) {
    // Request logging (método, caminho, status, duração, UA, bytes)
    sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
    start := time.Now()
    defer func() {
        dur := time.Since(start)
        ua := strings.TrimSpace(r.Header.Get("User-Agent"))
        logInfo("%s %s -> %d (%s) ua=%q bytes=%d", r.Method, r.URL.Path, sw.status, dur.String(), ua, sw.nbytes)
    }()
	w = sw
	path := r.URL.Path

    // Delegação por domínio (Admin, Users, UsersSpaces, Tools)
    // Observação: se alguma sub-rotina atender a rota, retornamos cedo.
    if handleAdminRoutes(w, r) { return }
    if handleUserAuthRoutes(w, r) { return }
    if handleUserSpacesRoutes(w, r) { return }

    switch {
	case path == "/" || path == "":
		rootHandler(w, r)
		return

	case path == "/healthz":
		healthHandler(w, r)
		return

    case path == "/openapi.json" && r.Method == http.MethodGet:
        // expõe o arquivo openapi.json da raiz do projeto
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        http.ServeFile(w, r, "openapi.json")
        return

    // (rotas Admin/Users/Spaces são delegadas acima)

    // ===== Tools: Faciendum (stubs com ACL) =====
    default:
        // Delegar para roteadores de Tools; retorna cedo se atender
        if handleAutomataRoutes(w, r) { return }
        if handleFaciendumRoutes(w, r) { return }
        // Roteamento por segmentos para stubs das tools
        parts := strings.Split(strings.Trim(path, "/"), "/")
        // Automata (CRUD com ACL): /user/spaces/{space_id}/automata/(keys|prompts|chats[/{id}])
        if len(parts) >= 5 && parts[0] == "user" && parts[1] == "spaces" && parts[3] == "automata" {
            spaceID, err := strconv.ParseInt(parts[2], 10, 64)
            if err != nil || spaceID <= 0 {
                writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_SPACE_ID"})
                return
            }
            userID, err := authenticateUser(r)
            if err != nil {
                writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()})
                return
            }
            if autdb == nil {
                writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "AUTOMATA_503", "message": "Banco do Automata indisponível"})
                return
            }
            resource := parts[4]
            var itemID int64 = 0
            if len(parts) >= 6 {
                if n, e := strconv.ParseInt(parts[5], 10, 64); e == nil && n > 0 { itemID = n }
            }
            switch resource {
            case "keys":
                if r.Method == http.MethodGet {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceRead); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    rows, err := autdb.Query(db.Rebind(`SELECT id, provider, name, created_at FROM automata_api_keys WHERE user_id = ? ORDER BY id DESC`), userID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    defer rows.Close()
                    items := make([]map[string]any, 0)
                    for rows.Next() {
                        var id int64; var provider, name string; var cAt time.Time
                        _ = rows.Scan(&id, &provider, &name, &cAt)
                        items = append(items, map[string]any{"id": id, "provider": provider, "name": name, "created_at": cAt})
                    }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
                    return
                } else if r.Method == http.MethodPost {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    var req struct{ Provider, Name, ApiKey string }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Provider) == "" || strings.TrimSpace(req.ApiKey) == "" {
                        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_KEY", "message": "provider e api_key são obrigatórios"})
                        return
                    }
                    res, err := autdb.Exec(db.Rebind(`INSERT INTO automata_api_keys (user_id, provider, name, api_key) VALUES (?,?,?,?)`), userID, strings.TrimSpace(req.Provider), strings.TrimSpace(req.Name), strings.TrimSpace(req.ApiKey))
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    kid, _ := res.LastInsertId()
                    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "api_key_id": kid})
                    return
                } else if r.Method == http.MethodDelete && itemID > 0 {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    res, err := autdb.Exec(db.Rebind(`DELETE FROM automata_api_keys WHERE id = ? AND user_id = ?`), itemID, userID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    n, _ := res.RowsAffected(); if n == 0 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                }
            case "prompts":
                if r.Method == http.MethodGet {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceRead); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    rows, err := autdb.Query(db.Rebind(`SELECT id, name, description, provider, api_key_id, created_at FROM automata_prompts WHERE user_id = ? ORDER BY id DESC`), userID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    defer rows.Close()
                    items := make([]map[string]any, 0)
                    for rows.Next() {
                        var id int64; var name, desc, provider sql.NullString; var keyID sql.NullInt64; var cAt time.Time
                        _ = rows.Scan(&id, &name, &desc, &provider, &keyID, &cAt)
                        items = append(items, map[string]any{"id": id, "name": name.String, "description": desc.String, "provider": provider.String, "api_key_id": keyID.Int64, "created_at": cAt})
                    }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
                    return
                } else if r.Method == http.MethodPost {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    var req struct{ Name, Description, Provider string; ApiKeyID int64 }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
                        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_PROMPT", "message": "name é obrigatório"})
                        return
                    }
                    if req.ApiKeyID > 0 {
                        var exists int
                        if err := autdb.QueryRow(db.Rebind(`SELECT 1 FROM automata_api_keys WHERE id = ? AND user_id = ?`), req.ApiKeyID, userID).Scan(&exists); err != nil {
                            writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_KEY_REF", "message": "api_key_id inválido"})
                            return
                        }
                    }
                    res, err := autdb.Exec(db.Rebind(`INSERT INTO automata_prompts (user_id, api_key_id, provider, name, description) VALUES (?,?,?,?,?)`), userID, nullIfZero(req.ApiKeyID), nullIfEmpty(req.Provider), strings.TrimSpace(req.Name), strings.TrimSpace(req.Description))
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    pid, _ := res.LastInsertId()
                    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "prompt_id": pid})
                    return
                } else if r.Method == http.MethodPatch && itemID > 0 {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    var req struct{ Name, Description, Provider string; ApiKeyID int64 }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    if req.ApiKeyID > 0 {
                        var exists int
                        if err := autdb.QueryRow(db.Rebind(`SELECT 1 FROM automata_api_keys WHERE id = ? AND user_id = ?`), req.ApiKeyID, userID).Scan(&exists); err != nil {
                            writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return
                        }
                    }
                    _, err := autdb.Exec(db.Rebind(`UPDATE automata_prompts SET name = COALESCE(NULLIF(?, ''), name), description = COALESCE(?, description), provider = COALESCE(NULLIF(?, ''), provider), api_key_id = COALESCE(?, api_key_id), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`), strings.TrimSpace(req.Name), nullIfEmpty(req.Description), nullIfEmpty(req.Provider), nullIfZero(req.ApiKeyID), itemID, userID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                } else if r.Method == http.MethodDelete && itemID > 0 {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    res, err := autdb.Exec(db.Rebind(`DELETE FROM automata_prompts WHERE id = ? AND user_id = ?`), itemID, userID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    n, _ := res.RowsAffected(); if n == 0 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                }
            case "chats":
                if r.Method == http.MethodGet {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceRead); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    rows, err := autdb.Query(db.Rebind(`SELECT id, prompt_id, message, response, created_at FROM automata_chats WHERE space_id = ? AND user_id = ? ORDER BY id DESC`), spaceID, userID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    defer rows.Close()
                    items := make([]map[string]any, 0)
                    for rows.Next() {
                        var id, pid int64; var msg string; var resp sql.NullString; var cAt time.Time
                        _ = rows.Scan(&id, &pid, &msg, &resp, &cAt)
                        items = append(items, map[string]any{"id": id, "prompt_id": pid, "message": msg, "response": resp.String, "created_at": cAt})
                    }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
                    return
                } else if r.Method == http.MethodPost {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    var req struct{ PromptID int64; Message string }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PromptID <= 0 || strings.TrimSpace(req.Message) == "" {
                        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_CHAT", "message": "prompt_id e message são obrigatórios"})
                        return
                    }
                    // Confere propriedade do prompt
                    var owner int64
                    if err := autdb.QueryRow(db.Rebind(`SELECT user_id FROM automata_prompts WHERE id = ? LIMIT 1`), req.PromptID).Scan(&owner); err != nil || owner != userID {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTOMATA_403_PROMPT"})
                        return
                    }
                    // Simula execução e persiste
                    resp := fmt.Sprintf("[automata] %s", strings.TrimSpace(req.Message))
                    res, err := autdb.Exec(db.Rebind(`INSERT INTO automata_chats (space_id, user_id, prompt_id, message, response) VALUES (?,?,?,?,?)`), spaceID, userID, req.PromptID, strings.TrimSpace(req.Message), resp)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    cid, _ := res.LastInsertId()
                    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "chat_id": cid, "response": resp})
                    return
                }
            }
        }
        if len(parts) >= 5 && parts[0] == "user" && parts[1] == "spaces" && parts[3] == "faciendum" {
            // /user/spaces/{space_id}/faciendum/(boards|tasks)
            spaceID, err := strconv.ParseInt(parts[2], 10, 64)
            if err != nil || spaceID <= 0 {
                writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_SPACE_ID"})
                return
            }
            userID, err := authenticateUser(r)
            if err != nil {
                writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()})
                return
            }
            resource := parts[4]
            var resourceID int64 = 0
            var hasID bool
            if len(parts) >= 6 {
                if n, e := strconv.ParseInt(parts[5], 10, 64); e == nil && n > 0 { resourceID = n; hasID = true }
            }
            if facdb == nil {
                writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "FACIENDUM_503", "message": "Banco do Faciendum indisponível"})
                return
            }
            switch resource {
            case "boards":
                if r.Method == http.MethodGet {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardRead); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    // Lista boards por espaço
                    rows, err := facdb.Query(db.Rebind(`SELECT id, name, created_at, updated_at FROM faciendum_boards WHERE space_id = ? ORDER BY id DESC`), spaceID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_LIST"}); return }
                    defer rows.Close()
                    items := make([]map[string]any, 0)
                    for rows.Next() {
                        var id int64; var name string; var cAt, uAt time.Time
                        _ = rows.Scan(&id, &name, &cAt, &uAt)
                        items = append(items, map[string]any{"id": id, "name": name, "created_at": cAt, "updated_at": uAt})
                    }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
                    return
                } else if r.Method == http.MethodPost {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    var req struct{ Name string `json:"name"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
                        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_BOARD", "message": "Nome é obrigatório"})
                        return
                    }
                    // Cria board e tracks padrão
                    tx, _ := facdb.Begin()
                    res, err := tx.Exec(db.Rebind(`INSERT INTO faciendum_boards (space_id, name) VALUES (?, ?)`), spaceID, strings.TrimSpace(req.Name))
                    if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_BOARD"}); return }
                    boardID, _ := res.LastInsertId()
                    // Trilhas padrão: A Fazer, Em Progresso, Feito (final)
                    defaults := []struct{ name string; isFinal bool }{
                        {"A Fazer", false}, {"Em Progresso", false}, {"Feito", true},
                    }
                    for i, t := range defaults {
                        if _, err := tx.Exec(db.Rebind(`INSERT INTO faciendum_tracks (board_id, name, position, is_final) VALUES (?,?,?,?)`), boardID, t.name, i, t.isFinal); err != nil {
                            _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_TRACKS"}); return
                        }
                    }
                    if err := tx.Commit(); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_TX"}); return }
                    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "board_id": boardID, "name": req.Name})
                    return
                } else if r.Method == http.MethodPatch && hasID {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    var req struct{ Name string `json:"name"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    // valida board pertence ao space
                    var sID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), resourceID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    _, err := facdb.Exec(db.Rebind(`UPDATE faciendum_boards SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), strings.TrimSpace(req.Name), resourceID)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                } else if r.Method == http.MethodDelete && hasID {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    // valida board pertence ao space e deleta em cascata
                    var sID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), resourceID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    tx, _ := facdb.Begin()
                    _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tasks WHERE board_id = ?`), resourceID)
                    _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tracks WHERE board_id = ?`), resourceID)
                    res, err := tx.Exec(db.Rebind(`DELETE FROM faciendum_boards WHERE id = ?`), resourceID)
                    if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    n, _ := res.RowsAffected(); if n == 0 { _ = tx.Rollback(); writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    _ = tx.Commit()
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                }
            case "tracks":
                if r.Method == http.MethodGet {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    boardIDStr := strings.TrimSpace(r.URL.Query().Get("board_id"))
                    if boardIDStr == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_BOARD_ID"}); return }
                    bid, e := strconv.ParseInt(boardIDStr, 10, 64); if e != nil || bid <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    // valida que o board pertence ao space
                    var sID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), bid).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    rows, err := facdb.Query(db.Rebind(`SELECT id, name, position, is_final, created_at, updated_at FROM faciendum_tracks WHERE board_id = ? ORDER BY position ASC, id ASC`), bid)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    defer rows.Close()
                    items := make([]map[string]any, 0)
                    for rows.Next() { var id int64; var name string; var pos int; var fin bool; var cAt, uAt time.Time; _ = rows.Scan(&id, &name, &pos, &fin, &cAt, &uAt); items = append(items, map[string]any{"id": id, "name": name, "position": pos, "is_final": fin, "created_at": cAt, "updated_at": uAt}) }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": items})
                    return
                } else if r.Method == http.MethodPost {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    var req struct{ BoardID int64 `json:"board_id"`; Name string `json:"name"`; Position *int `json:"position"`; IsFinal *bool `json:"is_final"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BoardID <= 0 || strings.TrimSpace(req.Name) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    // valida board pertence ao space
                    var sID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), req.BoardID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    // calcula posição
                    var maxPos int
                    _ = facdb.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tracks WHERE board_id = ?`), req.BoardID).Scan(&maxPos)
                    targetPos := maxPos + 1
                    if req.Position != nil && *req.Position >= 0 && *req.Position <= maxPos { targetPos = *req.Position }
                    tx, _ := facdb.Begin()
                    // se houver final e for inserir antes do final, ok; se is_final true, manda para o fim e zera outros finais
                    isFinal := false; if req.IsFinal != nil { isFinal = *req.IsFinal }
                    if isFinal {
                        targetPos = maxPos + 1
                        _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET is_final = FALSE WHERE board_id = ?`), req.BoardID)
                    } else {
                        _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position + 1 WHERE board_id = ? AND position >= ?`), req.BoardID, targetPos)
                    }
                    res, err := tx.Exec(db.Rebind(`INSERT INTO faciendum_tracks (board_id, name, position, is_final) VALUES (?,?,?,?)`), req.BoardID, strings.TrimSpace(req.Name), targetPos, isFinal)
                    if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    tid, _ := res.LastInsertId(); _ = tx.Commit()
                    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "track_id": tid, "position": targetPos, "is_final": isFinal})
                    return
                } else if r.Method == http.MethodPatch && hasID {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    var req struct{ Name *string `json:"name"`; Position *int `json:"position"`; IsFinal *bool `json:"is_final"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    // carrega track e board
                    var boardID int64; var oldPos int; var wasFinal bool
                    if err := facdb.QueryRow(db.Rebind(`SELECT board_id, position, is_final FROM faciendum_tracks WHERE id = ?`), resourceID).Scan(&boardID, &oldPos, &wasFinal); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    var sID int64; if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), boardID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    tx, _ := facdb.Begin()
                    // nome
                    if req.Name != nil { _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET name = ? WHERE id = ?`), strings.TrimSpace(*req.Name), resourceID) }
                    // is_final
                    if req.IsFinal != nil {
                        if *req.IsFinal {
                            // torna final e move para o fim
                            var maxPos int; _ = tx.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tracks WHERE board_id = ?`), boardID).Scan(&maxPos)
                            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET is_final = FALSE WHERE board_id = ?`), boardID)
                            // compacta buraco
                            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position - 1 WHERE board_id = ? AND position > ?`), boardID, oldPos)
                            oldPos = maxPos // moving to end so old position used above
                            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = ? , is_final = TRUE WHERE id = ?`), maxPos, resourceID)
                        } else {
                            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET is_final = FALSE WHERE id = ?`), resourceID)
                        }
                    }
                    // position
                    if req.Position != nil {
                        var maxPos int; _ = tx.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tracks WHERE board_id = ?`), boardID).Scan(&maxPos)
                        pos := *req.Position; if pos < 0 { pos = 0 }; if pos > maxPos { pos = maxPos }
                        if pos < oldPos {
                            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position + 1 WHERE board_id = ? AND position >= ? AND position < ? AND id <> ?`), boardID, pos, oldPos, resourceID)
                        } else if pos > oldPos {
                            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position - 1 WHERE board_id = ? AND position <= ? AND position > ? AND id <> ?`), boardID, pos, oldPos, resourceID)
                        }
                        _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = ? WHERE id = ?`), pos, resourceID)
                    }
                    if err := tx.Commit(); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                } else if r.Method == http.MethodDelete && hasID {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    // só permite deletar track vazia
                    var boardID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT board_id FROM faciendum_tracks WHERE id = ?`), resourceID).Scan(&boardID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    var cnt int; _ = facdb.QueryRow(db.Rebind(`SELECT COUNT(1) FROM faciendum_tasks WHERE track_id = ?`), resourceID).Scan(&cnt)
                    if cnt > 0 { writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "FACIENDUM_409_TRACK_NOT_EMPTY"}); return }
                    // compacta posições
                    var pos int; _ = facdb.QueryRow(db.Rebind(`SELECT position FROM faciendum_tracks WHERE id = ?`), resourceID).Scan(&pos)
                    tx, _ := facdb.Begin()
                    _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tracks WHERE id = ?`), resourceID)
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position - 1 WHERE board_id = ? AND position > ?`), boardID, pos)
                    _ = tx.Commit()
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                }
            case "tasks":
                if r.Method == http.MethodGet {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskRead); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    // Filtro opcional por board_id
                    boardIDStr := r.URL.Query().Get("board_id")
                    q := `SELECT id, board_id, track_id, title, description, position, created_at, updated_at FROM faciendum_tasks WHERE space_id = ?`
                    args := []any{spaceID}
                    if b := strings.TrimSpace(boardIDStr); b != "" {
                        if bid, err := strconv.ParseInt(b, 10, 64); err == nil && bid > 0 {
                            q += ` AND board_id = ?`
                            args = append(args, bid)
                        }
                    }
                    q += ` ORDER BY board_id, position, id`
                    rows, err := facdb.Query(db.Rebind(q), args...)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_LIST_TASKS"}); return }
                    defer rows.Close()
                    items := make([]map[string]any, 0)
                    for rows.Next() {
                        var id, bid, tid int64; var title, desc sql.NullString; var pos int; var cAt, uAt time.Time
                        _ = rows.Scan(&id, &bid, &tid, &title, &desc, &pos, &cAt, &uAt)
                        items = append(items, map[string]any{"id": id, "board_id": bid, "track_id": tid, "title": title.String, "description": desc.String, "position": pos, "created_at": cAt, "updated_at": uAt})
                    }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
                    return
                } else if r.Method == http.MethodPost {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil {
                        writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"})
                        return
                    }
                    var req struct{ BoardID int64 `json:"board_id"`; Title string `json:"title"`; Description string `json:"description"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BoardID <= 0 || strings.TrimSpace(req.Title) == "" {
                        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_TASK", "message": "board_id e title são obrigatórios"})
                        return
                    }
                    // Descobre primeira track do board
                    var firstTrackID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT id FROM faciendum_tracks WHERE board_id = ? ORDER BY position ASC LIMIT 1`), req.BoardID).Scan(&firstTrackID); err != nil {
                        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_TRACK", "message": "Board inválido ou sem trilhas"})
                        return
                    }
                    res, err := facdb.Exec(db.Rebind(`INSERT INTO faciendum_tasks (space_id, board_id, track_id, title, description, position) VALUES (?,?,?,?,?,?)`), spaceID, req.BoardID, firstTrackID, strings.TrimSpace(req.Title), strings.TrimSpace(req.Description), 0)
                    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_TASK"}); return }
                    taskID, _ := res.LastInsertId()
                    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "task_id": taskID})
                    return
                } else if r.Method == http.MethodPatch && hasID {
                    // Atualização simples de título/descrição
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    var req struct{ Title *string `json:"title"`; Description *string `json:"description"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    // confere task pertence ao space
                    var sID int64; if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_tasks WHERE id = ?`), resourceID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    if req.Title == nil && req.Description == nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    if req.Title != nil { _, _ = facdb.Exec(db.Rebind(`UPDATE faciendum_tasks SET title = ? WHERE id = ?`), strings.TrimSpace(*req.Title), resourceID) }
                    if req.Description != nil { _, _ = facdb.Exec(db.Rebind(`UPDATE faciendum_tasks SET description = ? WHERE id = ?`), strings.TrimSpace(*req.Description), resourceID) }
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                } else if r.Method == http.MethodDelete && hasID {
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    // compacta posições na track
                    var trackID int64; var pos int
                    if err := facdb.QueryRow(db.Rebind(`SELECT track_id, position FROM faciendum_tasks WHERE id = ? AND space_id = ?`), resourceID, spaceID).Scan(&trackID, &pos); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    tx, _ := facdb.Begin()
                    _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tasks WHERE id = ?`), resourceID)
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET position = position - 1 WHERE track_id = ? AND position > ?`), trackID, pos)
                    _ = tx.Commit()
                    writeJSON(w, http.StatusOK, map[string]any{"success": true})
                    return
                } else if hasID && len(parts) >= 7 && parts[6] == "move" && (r.Method == http.MethodPatch || r.Method == http.MethodPost) {
                    // Mover task para outra track e/ou posição
                    if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return }
                    var req struct{ ToTrackID int64 `json:"to_track_id"`; Position *int `json:"position"` }
                    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ToTrackID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return }
                    // Carrega task atual
                    var curTrackID, curBoardID int64; var curPos int
                    if err := facdb.QueryRow(db.Rebind(`SELECT track_id, board_id, position FROM faciendum_tasks WHERE id = ? AND space_id = ?`), resourceID, spaceID).Scan(&curTrackID, &curBoardID, &curPos); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return }
                    // Valida destino pertence ao mesmo board
                    var destBoardID int64
                    if err := facdb.QueryRow(db.Rebind(`SELECT board_id FROM faciendum_tracks WHERE id = ?`), req.ToTrackID).Scan(&destBoardID); err != nil || destBoardID != curBoardID { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_MOVE_DEST"}); return }
                    tx, _ := facdb.Begin()
                    // Compacta origem
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET position = position - 1 WHERE track_id = ? AND position > ?`), curTrackID, curPos)
                    // Calcula nova posição
                    var maxPos int; _ = tx.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tasks WHERE track_id = ?`), req.ToTrackID).Scan(&maxPos)
                    newPos := maxPos + 1
                    if req.Position != nil && *req.Position >= 0 && *req.Position <= maxPos {
                        newPos = *req.Position
                        _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET position = position + 1 WHERE track_id = ? AND position >= ?`), req.ToTrackID, newPos)
                    }
                    // Atualiza task
                    _, err := tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET track_id = ?, position = ? WHERE id = ?`), req.ToTrackID, newPos, resourceID)
                    if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return }
                    _ = tx.Commit()
                    writeJSON(w, http.StatusOK, map[string]any{"success": true, "position": newPos, "track_id": req.ToTrackID})
                    return
                }
            case "task-move":
                // legacy marker
                writeJSON(w, http.StatusNotFound, map[string]any{"success": false})
                return
            }
        }

	// Compatibilidade com rewrites que possam incluir prefixo /api
	case strings.HasPrefix(path, "/api/"):
		r.URL.Path = strings.TrimPrefix(path, "/api")
		Handler(w, r)
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]any{
		"success":    false,
		"code":       "HTTP_404",
		"message":    "Rota não encontrada",
		"locale_key": "error.not_found",
		"path":       path,
	})
}

// Instâncias de singletons para ambiente serverless.
var (
    inited  = false
    service *authsvc.Service
    cfg     *config.Config
    sqldb   *sql.DB
    mailer  *emailsvc.Service
    facdb   *sql.DB
    autdb   *sql.DB
)

// init prepara dependências (DB, migrações, serviço) na primeira invocação.
func init() {
	if inited {
		return
	}
	// Em desenvolvimento, preferimos que o .env local sobrescreva variáveis já definidas
	_ = godotenv.Overload()
	cfg = config.Load()
    dbURL := os.Getenv("DATABASE_URL")
    if dbURL == "" { dbURL = cfg.DatabaseURL }
    // Em serverless (Vercel/Lambda), se não houver DATABASE_URL, use SQLite em /tmp (área gravável)
    if strings.TrimSpace(dbURL) == "" {
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            dbURL = "/tmp/auth_fast_api.db"
        }
    }
    if os.Getenv("VERCEL") != "" {
        // Log leve para depuração (não imprime DSN completo)
        target := "custom"
        if strings.Contains(dbURL, "/tmp/") || strings.HasPrefix(dbURL, "/tmp") { target = "sqlite-/tmp" }
        logInfo("serverless init: selecting database target=%s", target)
    }
	var err error
	sqldb, err = db.Connect(dbURL)
	if err != nil {
		log.Printf("db connect error: %v", err)
		return
	}
	if err := db.Migrate(context.Background(), sqldb); err != nil {
		log.Printf("db migrate error: %v", err)
		return
	}
	// Seed root admin se informado nas envs
	seedRootAdmin(sqldb)

	accessTTL := parseIntEnv("TOKEN_ACCESS_EXPIRE_SECONDS", 1800)
	refreshTTL := parseIntEnv("TOKEN_REFRESH_EXPIRE_SECONDS", 2592000)
	service = authsvc.New(sqldb, cfg.SecretKey, timeSeconds(accessTTL), timeSeconds(refreshTTL))
    // E-mail service
    mailer = emailsvc.FromConfig(cfg)
    if mailer == nil {
        logInfo("email disabled: missing EMAIL_SERVER_SMTP_HOST; skipping mail send")
    }
    // Redis init (rate limit / lockout)
    if err := kv.Init(os.Getenv("REDIS_URL"), cfg.RedisHost, cfg.RedisPort, cfg.RedisPass, cfg.RedisTLS); err != nil {
        logWarn("redis init failed: %v", err)
    }
    // Faciendum DB init
    facURL := os.Getenv("FACIENDUM_DATABASE_URL")
    if strings.TrimSpace(facURL) == "" {
        // fallback: em serverless, usar /tmp; local, usar arquivo padrão
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            facURL = "/tmp/faciendum.db"
        } else {
            facURL = "faciendum.db"
        }
    }
    if dbconn, err := db.Connect(facURL); err != nil {
        logWarn("faciendum db connect failed: %v", err)
    } else {
        facdb = dbconn
        // Migrar schema do Faciendum
        if err := faciendum.Migrate(context.Background(), facdb, db.IsPostgres()); err != nil {
            logWarn("faciendum migrate failed: %v", err)
        }
    }
    // Automata DB init (opcional; stubs usam ACL e podem ignorar persistência)
    autURL := os.Getenv("AUTOMATA_DATABASE_URL")
    if strings.TrimSpace(autURL) == "" {
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            autURL = "/tmp/automata.db"
        } else { autURL = "automata.db" }
    }
    if dbconn, err := db.Connect(autURL); err != nil {
        logWarn("automata db connect failed: %v", err)
    } else {
        autdb = dbconn
        if err := automata.Migrate(context.Background(), autdb, db.IsPostgres()); err != nil {
            logWarn("automata migrate failed: %v", err)
        }
    }
    inited = true
}

// seedRootAdmin cria o usuário root se não existir.
func seedRootAdmin(sqldb *sql.DB) {
	user := os.Getenv("ROOT_AUTH_USER")
	email := os.Getenv("ROOT_AUTH_EMAIL")
	pass := os.Getenv("ROOT_AUTH_PASSWORD")
	if user == "" || email == "" || pass == "" {
		return
	}
	var (
		id       int64
		verified bool
	)
	err := sqldb.QueryRow(db.Rebind(`SELECT id, is_verified FROM admins WHERE username = ? LIMIT 1`), user).Scan(&id, &verified)
	switch err {
	case nil:
		if !verified {
			if _, e := sqldb.Exec(db.Rebind(`UPDATE admins SET is_verified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), true, id); e != nil {
				log.Printf("seed root admin: failed to activate existing user: %v", e)
			} else {
				log.Printf("seed root admin: activated existing user '%s'", user)
			}
		}
		return
    case sql.ErrNoRows:
        // create new active root user
        hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
        // create verified root user with lifetime plan
        if _, e := sqldb.Exec(db.Rebind(`INSERT INTO admins (email, username, password_hash, system_role, subscription_plan, expires_at, is_verified) VALUES (?,?,?,?,?,?,?)`), email, user, string(hash), "root", "lifetime", nil, true); e != nil {
            log.Printf("seed root admin failed: %v", e)
        }
        return
	default:
		log.Printf("seed root admin select failed: %v", err)
		return
	}
}

// parseIntEnv obtém int de env com default.
func parseIntEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// timeSeconds converte segundos em time.Duration.
func timeSeconds(s int) time.Duration { return time.Duration(s) * time.Second }

// authenticateAdmin valida o header Authorization: Bearer e retorna (adminID, systemRole).
func authenticateAdmin(r *http.Request) (int64, string, error) {
    h := r.Header.Get("Authorization")
    if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
        return 0, "", errors.New("token ausente")
    }
    tokenStr := strings.TrimSpace(h[len("Bearer "):])
    // 1) Tenta JWT (tokens de acesso existentes)
    if tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("algoritmo inválido")
        }
        return []byte(cfg.SecretKey), nil
    }); err == nil && tok != nil && tok.Valid {
        if claims, ok := tok.Claims.(jwt.MapClaims); ok {
            sub, _ := claims["sub"].(string)
            sro, _ := claims["sro"].(string)
            if sub != "" && sro != "" {
                var id int64 = 0
                if strings.HasPrefix(sub, "admin|") {
                    parts := strings.SplitN(sub, "|", 2)
                    if len(parts) == 2 {
                        if n, err := strconv.ParseInt(parts[1], 10, 64); err == nil { id = n }
                    }
                }
                if id > 0 {
                    var verified bool
                    if err := sqldb.QueryRow(db.Rebind(`SELECT is_verified FROM admins WHERE id = ? LIMIT 1`), id).Scan(&verified); err != nil {
                        return 0, "", errors.New("conta inexistente")
                    }
                    if !verified { return 0, "", errors.New("conta não verificada") }
                }
                return id, sro, nil
            }
        }
    }
    // 2) Fallback: token de API (PAT) – tratamos como opaco + hash no banco
    hash := sha256.Sum256([]byte(tokenStr))
    var (
        adminID int64
        role    string
        verified bool
    )
    err := sqldb.QueryRow(db.Rebind(`
        SELECT a.id, a.system_role, a.is_verified
        FROM admins_api_tokens t
        JOIN admins a ON a.id = t.admin_id
        WHERE t.token_hash = ?
          AND (t.expires_at IS NULL OR t.expires_at > CURRENT_TIMESTAMP)
          AND t.revoked_at IS NULL
        LIMIT 1
    `), hex.EncodeToString(hash[:])).Scan(&adminID, &role, &verified)
    if err != nil {
        return 0, "", errors.New("token inválido")
    }
    if !verified {
        return 0, "", errors.New("conta não verificada")
    }
    // Best-effort: atualiza last_used_at (ignora erro)
    _, _ = sqldb.Exec(db.Rebind(`UPDATE admins_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?`), hex.EncodeToString(hash[:]))
    return adminID, role, nil
}

// canManageSystemRole verifica se actingRole possui prioridade estritamente maior que targetRole.
func canManageSystemRole(actingRole, targetRole string) bool {
	prio := map[string]int{"guest": 0, "user": 1, "admin": 2, "root": 3}
	a := prio[strings.ToLower(strings.TrimSpace(actingRole))]
	t := prio[strings.ToLower(strings.TrimSpace(targetRole))]
	return a > t
}

// statusWriter captura status/bytes para logging.
type statusWriter struct {
	http.ResponseWriter
	status int
	nbytes int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.nbytes += n
	return n, err
}

// Logging helpers com níveis simples (DEBUG, INFO, WARN, ERROR)
func logEnabled(level string) bool {
	order := map[string]int{"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
	cur := strings.ToUpper(strings.TrimSpace(cfg.LogLevel))
	if cur == "" {
		cur = "INFO"
	}
	return order[strings.ToUpper(level)] >= order[cur]
}

func logDebug(format string, args ...any) {
	if logEnabled("DEBUG") {
		log.Printf("[DEBUG] "+format, args...)
	}
}
func logInfo(format string, args ...any) {
	if logEnabled("INFO") {
		log.Printf("[INFO]  "+format, args...)
	}
}
func logWarn(format string, args ...any) {
	if logEnabled("WARN") {
		log.Printf("[WARN]  "+format, args...)
	}
}
func logError(format string, args ...any) {
	if logEnabled("ERROR") {
		log.Printf("[ERROR] "+format, args...)
	}
}

// generateNumericPassword cria uma senha aleatória com dígitos [0-9] de comprimento n.
func generateNumericPassword(n int) string {
	if n <= 0 {
		return ""
	}
	const digits = "0123456789"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		r, err := crand.Int(crand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			// fallback: usa o timestamp para reduzir chance de repetição
			b[i] = digits[int(time.Now().UnixNano())%10]
			continue
		}
		b[i] = digits[r.Int64()]
	}
	return string(b)
}

// generateVerificationCode cria um código único em hex com comprimento exato desejado (ex.: 64 chars).
func generateVerificationCode(length int) (string, error) {
	if length <= 0 || length%2 != 0 {
		return "", errors.New("invalid verification code length")
	}
	b := make([]byte, length/2)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// passwordPolicyStrict ativa validação de complexidade quando PASSWORD_POLICY_STRICT=true/1
func passwordPolicyStrict() bool {
    v := strings.TrimSpace(strings.ToLower(os.Getenv("PASSWORD_POLICY_STRICT")))
    return v == "true" || v == "1" || v == "yes"
}

// validatePassword aplica política mínima (>=8) e, se estrita, requer classes: minúscula, maiúscula, dígito e especial.
func validatePassword(pw string) error {
    if len(pw) < contants.DefaultGeneratedPasswordLength {
        return errors.New("Senha deve ter pelo menos 8 caracteres")
    }
    if !passwordPolicyStrict() {
        return nil
    }
    hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
    for _, r := range pw {
        switch {
        case r >= 'a' && r <= 'z':
            hasLower = true
        case r >= 'A' && r <= 'Z':
            hasUpper = true
        case r >= '0' && r <= '9':
            hasDigit = true
        default:
            hasSpecial = true
        }
    }
    if hasLower && hasUpper && hasDigit && hasSpecial {
        return nil
    }
    return errors.New("Senha deve conter maiúscula, minúscula, número e caractere especial")
}

// generateStrongPassword cria uma senha aleatória garantindo presença de classes.
func generateStrongPassword(n int) string {
    if n < 8 { n = 12 }
    lower := []rune("abcdefghijklmnopqrstuvwxyz")
    upper := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    digits := []rune("0123456789")
    special := []rune("!@#$%^&*()-_=+[]{};:,.?/|~")
    all := append(append(append(lower, upper...), digits...), special...)

    pick := func(set []rune) rune {
        r, err := crand.Int(crand.Reader, big.NewInt(int64(len(set))))
        if err != nil { return set[int(time.Now().UnixNano())%len(set)] }
        return set[r.Int64()]
    }
    out := make([]rune, n)
    // Garante uma de cada
    out[0] = pick(lower)
    out[1] = pick(upper)
    out[2] = pick(digits)
    out[3] = pick(special)
    for i := 4; i < n; i++ {
        out[i] = pick(all)
    }
    for i := n - 1; i > 0; i-- {
        r, err := crand.Int(crand.Reader, big.NewInt(int64(i+1)))
        j := i
        if err == nil { j = int(r.Int64()) }
        out[i], out[j] = out[j], out[i]
    }
    return string(out)
}

// buildVerifyURL monta a URL pública para verificação, se base estiver configurada.
func buildVerifyURL(r *http.Request, code string) string {
	if strings.TrimSpace(code) == "" {
		return ""
	}
	base := strings.TrimRight(cfg.PublicBaseURL, "/")
	if base == "" {
		base = strings.TrimRight(requestBaseURL(r), "/")
	}
	if base == "" {
		return ""
	}
	return base + "/admin/code-verified/" + code
}

// requestBaseURL tenta deduzir a URL base (scheme+host) da requisição.
// Prioriza cabeçalhos de proxy (X-Forwarded-Proto/Host), depois Host.
func requestBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		scheme = "http"
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

// clientIP extrai IP do X-Forwarded-For ou RemoteAddr
func clientIP(r *http.Request) string {
    if r == nil { return "" }
    if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
        parts := strings.Split(xff, ",")
        if len(parts) > 0 { return strings.TrimSpace(parts[0]) }
    }
    host := r.RemoteAddr
    if i := strings.LastIndex(host, ":"); i > 0 { host = host[:i] }
    return host
}

// authenticateUser valida Authorization: Bearer (JWT) para usuários e retorna userID
func authenticateUser(r *http.Request) (int64, error) {
    h := r.Header.Get("Authorization")
    if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
        return 0, errors.New("token ausente")
    }
    tokenStr := strings.TrimSpace(h[len("Bearer "):])
    tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, errors.New("algoritmo inválido") }
        return []byte(cfg.SecretKey), nil
    })
    if err != nil || tok == nil || !tok.Valid { return 0, errors.New("token inválido") }
    claims, ok := tok.Claims.(jwt.MapClaims)
    if !ok { return 0, errors.New("claims inválidas") }
    sub, _ := claims["sub"].(string)
    if !strings.HasPrefix(sub, "user|") { return 0, errors.New("escopo inválido") }
    parts := strings.SplitN(sub, "|", 2)
    if len(parts) != 2 { return 0, errors.New("sub inválido") }
    id, err := strconv.ParseInt(parts[1], 10, 64)
    if err != nil || id <= 0 { return 0, errors.New("sub inválido") }
    var verified bool
    if err := sqldb.QueryRow(db.Rebind(`SELECT is_verified FROM users WHERE id = ? LIMIT 1`), id).Scan(&verified); err != nil { return 0, errors.New("conta inexistente") }
    if !verified { return 0, errors.New("conta não verificada") }
    return id, nil
}

func generateUsersSpaceHash(n int) string {
    if n <= 0 || n%2 != 0 { n = contants.UsersSpaceHashLength }
    b := make([]byte, n/2); _, _ = crand.Read(b)
    return hex.EncodeToString(b)
}

// ===== ACL por UsersSpace =====

// Ações básicas usadas pelas tools e operações em espaço
const (
    actionSpaceRead   = "space:read"
    actionSpaceWrite  = "space:write"   // renomear, configurar
    actionMemberManage= "member:manage" // convites, papéis, remoções
    actionBoardRead   = "board:read"
    actionBoardWrite  = "board:write"
    actionTaskRead    = "task:read"
    actionTaskWrite   = "task:write"
)

// Matriz de permissões por papel
var spaceACL = map[string]map[string]bool{
    // Owner do espaço: tudo
    "owner": {actionSpaceRead: true, actionSpaceWrite: true, actionMemberManage: true, actionBoardRead: true, actionBoardWrite: true, actionTaskRead: true, actionTaskWrite: true},
    // Admin (membro): gerencia conteúdo (boards/tasks), mas não membros/ownership
    "admin": {actionSpaceRead: true, actionBoardRead: true, actionBoardWrite: true, actionTaskRead: true, actionTaskWrite: true},
    // User: pode operar tarefas e mover no kanban; sem gestão de boards avançada
    "user":  {actionSpaceRead: true, actionBoardRead: true, actionTaskRead: true, actionTaskWrite: true},
    // Guest: somente leitura
    "guest": {actionSpaceRead: true, actionBoardRead: true, actionTaskRead: true},
}

// getUserSpaceRole retorna o papel do usuário no espaço: owner|admin|user|guest|""
func getUserSpaceRole(ctx context.Context, userID, spaceID int64) (string, error) {
    if userID <= 0 || spaceID <= 0 { return "", errors.New("ids inválidos") }
    var ownerID int64
    if err := sqldb.QueryRowContext(ctx, db.Rebind(`SELECT owner_user_id FROM users_spaces WHERE id = ? LIMIT 1`), spaceID).Scan(&ownerID); err != nil {
        if err == sql.ErrNoRows { return "", errors.New("espaço inexistente") }
        return "", err
    }
    if ownerID == userID { return "owner", nil }
    var role string
    err := sqldb.QueryRowContext(ctx, db.Rebind(`SELECT role FROM users_spaces_members WHERE space_id = ? AND user_id = ? LIMIT 1`), spaceID, userID).Scan(&role)
    if err == sql.ErrNoRows { return "", nil }
    if err != nil { return "", err }
    return strings.ToLower(strings.TrimSpace(role)), nil
}

func hasSpacePermission(role, action string) bool {
    role = strings.ToLower(strings.TrimSpace(role))
    if role == "" { return false }
    perms := spaceACL[role]
    return perms != nil && perms[action]
}

// requireSpacePermission valida permissão; retorna erro se negar
func requireSpacePermission(ctx context.Context, userID, spaceID int64, action string) error {
    role, err := getUserSpaceRole(ctx, userID, spaceID)
    if err != nil { return err }
    if !hasSpacePermission(role, action) { return errors.New("forbidden") }
    return nil
}

// Helpers para tratar nulos em INSERT/UPDATE
func nullIfZero(n int64) any { if n == 0 { return nil }; return n }
func nullIfEmpty(s string) any {
    t := strings.TrimSpace(s)
    if t == "" { return nil }
    return t
}
