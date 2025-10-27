package httpapi

import (
    "context"
    crand "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/lfcontato/auth_fast_api/internal/contants"
    "github.com/lfcontato/auth_fast_api/internal/db"
    "github.com/lfcontato/auth_fast_api/internal/kv"
    emailsvc "github.com/lfcontato/auth_fast_api/internal/services/email"
    "golang.org/x/crypto/bcrypt"
)

// userCreateHandler: POST /user
// Cria um novo usuário a partir de username, email, password e confirm_password.
// Regras:
//  - Senhas devem coincidir e obedecer à política (validatePassword).
//  - Username e email são normalizados (username trim; email lowercase).
//  - Define defaults: tools_role='user', subscription_plan='trial' com expires_at conforme computeExpires.
//  - Marca is_verified=false e gera código em users_verifications (TTL cfg.VerifyCodeTTLHours), enviando e‑mail se mailer estiver configurado.
func userCreateHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "code": "HTTP_405", "message": "Método não permitido"})
        return
    }
    var req struct{
        Email           string `json:"email"`
        Username        string `json:"username"`
        Password        string `json:"password"`
        ConfirmPassword string `json:"confirm_password"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_JSON", "message": "JSON inválido"})
        return
    }
    req.Email = strings.TrimSpace(strings.ToLower(req.Email))
    req.Username = strings.TrimSpace(strings.ToLower(req.Username))
    req.Password = strings.TrimSpace(req.Password)
    req.ConfirmPassword = strings.TrimSpace(req.ConfirmPassword)
    if req.Email == "" || req.Username == "" || req.Password == "" || req.ConfirmPassword == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_REQUIRED", "message": "Campos obrigatórios ausentes"})
        return
    }
    if req.Password != req.ConfirmPassword {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_PW_MISMATCH", "message": "Senhas não conferem"})
        return
    }
    if err := validatePassword(req.Password); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_PW_POLICY", "message": err.Error()})
        return
    }
    hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_HASH", "message": "Falha ao processar senha"}); return }

    // Defaults de perfil
    toolsRole := "user"
    plan := "trial"
    var expires any = nil
    if plan != "lifetime" {
        e := computeExpires(plan, time.Now())
        expires = e
    }

    // Inserir usuário
    var newID int64
    if db.IsPostgres() {
        q := db.Rebind(`INSERT INTO users (email, username, password_hash, tools_role, subscription_plan, expires_at, is_verified) VALUES (?,?,?,?,?,?,?) RETURNING id`)
        if err := sqldb.QueryRow(q, req.Email, req.Username, string(hash), toolsRole, plan, expires, false).Scan(&newID); err != nil {
            writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_DUP", "message": "Email ou username já existente"})
            return
        }
    } else {
        res, err := sqldb.Exec(db.Rebind(`INSERT INTO users (email, username, password_hash, tools_role, subscription_plan, expires_at, is_verified) VALUES (?,?,?,?,?,?,?)`), req.Email, req.Username, string(hash), toolsRole, plan, expires, false)
        if err != nil {
            writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_DUP", "message": "Email ou username já existente"})
            return
        }
        newID, _ = res.LastInsertId()
    }

    // Gera e persiste código de verificação
    code, cerr := generateVerificationCode(contants.VerificationCodeLength)
    if cerr == nil {
        ttl := time.Duration(cfg.VerifyCodeTTLHours) * time.Hour
        _, _ = sqldb.Exec(db.Rebind(`INSERT INTO users_verifications (user_id, code, expires_at) VALUES (?,?,?)`), newID, code, time.Now().Add(ttl))
        // E‑mail de boas‑vindas/verificação (melhor esforço)
        if mailer != nil && !isTestEmail(req.Email) {
            // Monta link de verificação que aponta para o endpoint de verificação por link
            base := strings.TrimRight(selectRedirectBaseURL(r), "/")
            var verifyURL string
            pathPrefix := ""
            if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" { pathPrefix = "/api" }
            if base != "" {
                q := url.Values{}
                // Aceita login por e-mail ou username no endpoint
                q.Set("login", req.Email)
                q.Set("code", code)
                verifyURL = base + pathPrefix + "/user/auth/verify-link?" + q.Encode()
            }
            data := map[string]any{
                "Title":             "Bem-vindo(a)",
                "Message":           "Use o botão abaixo ou o código para verificar sua conta.",
                "Email":             req.Email,
                "Username":          req.Username,
                "VerificationCode":  code,
                // Template genérico suporta CTA via ActionURL/ActionText e nota extra
                "ActionURL":         verifyURL,
                "ActionText":        "Verificar conta",
                "ExtraNote":         fmt.Sprintf("Seu código de verificação: %s", code),
            }
            ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
            defer cancel()
            _ = mailer.Send(ctx, emailsvc.Params{To: []string{req.Email}, Subject: contants.EmailSubjectUserCreated, TemplateName: cfg.EmailTemplateName, Data: data})
        }
    }

    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "user_id": newID, "username": req.Username, "email": req.Email})
}

// userAuthTokenHandler: POST /user/auth/token
// Autentica usuário por username/password e emite par de tokens.
func userAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
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
func userAuthRefreshHandler(w http.ResponseWriter, r *http.Request) {
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
func userAuthVerifyHandler(w http.ResponseWriter, r *http.Request) {
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
func userAuthVerifyLinkHandler(w http.ResponseWriter, r *http.Request) {
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
func userAuthPasswordRecoveryHandler(w http.ResponseWriter, r *http.Request) {
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
        base := strings.TrimRight(selectRedirectBaseURL(r), "/")
        var verifyURL string
        pathPrefix := ""
        if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" { pathPrefix = "/api" }
        if base != "" {
            q := url.Values{}
            q.Set("login", req.Email)
            q.Set("code", code)
            verifyURL = base + pathPrefix + "/user/auth/verify-link?" + q.Encode()
        }
        data := map[string]any{
            "Title":             "Recuperação de senha",
            "Message":           "Use a nova senha e o código para verificar sua conta.",
            "Email":             req.Email,
            "Username":          username,
            "Password":          newPass,
            "VerificationCode":  code,
            "ActionURL":         verifyURL,
            "ActionText":        "Verificar conta",
            "ExtraNote":         fmt.Sprintf("Seu código de verificação: %s", code),
        }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second); defer cancel()
        _ = mailer.Send(ctx, emailsvc.Params{To: []string{req.Email}, Subject: contants.EmailSubjectPasswordRecovery, TemplateName: cfg.EmailTemplateName, Data: data})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

// userAuthVerificationCodeHandler: POST /user/auth/verification-code (reenvio)
func userAuthVerificationCodeHandler(w http.ResponseWriter, r *http.Request) {
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
        base := strings.TrimRight(selectRedirectBaseURL(r), "/")
        var verifyURL string
        pathPrefix := ""
        if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" { pathPrefix = "/api" }
        if base != "" {
            q := url.Values{}
            q.Set("login", email)
            q.Set("code", code)
            verifyURL = base + pathPrefix + "/user/auth/verify-link?" + q.Encode()
        }
        data := map[string]any{
            "Title":            "Verificação de conta",
            "Message":          "Clique no botão abaixo ou use o código para verificar sua conta.",
            "Email":            email,
            "Username":         username,
            "VerificationCode": code,
            "ActionURL":        verifyURL,
            "ActionText":       "Verificar conta",
            "ExtraNote":        fmt.Sprintf("Seu código de verificação: %s", code),
        }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second); defer cancel()
        _ = mailer.Send(ctx, emailsvc.Params{To: []string{email}, Subject: contants.EmailSubjectUserCreated, TemplateName: cfg.EmailTemplateName, Data: data})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

// signUserAccessTokenWithExp cria JWT de usuário com claims pedidas: uid, email, user=true
func signUserAccessTokenWithExp(userID int64, email, sessionID string, exp time.Time) (string, error) {
    claims := jwt.MapClaims{
        "sub":  "user|" + strconv.FormatInt(userID, 10),
        "uid":  userID,
        "email": email,
        "user": true,
        "sid":  sessionID,
        "exp":  exp.Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(cfg.SecretKey))
}
