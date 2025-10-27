package httpapi

import (
    "context"
    crand "crypto/rand"
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/lfcontato/auth_fast_api/internal/contants"
    "github.com/lfcontato/auth_fast_api/internal/db"
    "github.com/lfcontato/auth_fast_api/internal/kv"
    emailsvc "github.com/lfcontato/auth_fast_api/internal/services/email"
    "golang.org/x/crypto/bcrypt"
)

func adminAuthTokenHandler(w http.ResponseWriter, r *http.Request)                 { adminAuthTokenHandler_impl(w, r) }
func adminAuthRefreshHandler(w http.ResponseWriter, r *http.Request)               { adminAuthRefreshHandler_impl(w, r) }
func adminAuthMFAVerifyHandler(w http.ResponseWriter, r *http.Request)             { adminAuthMFAVerifyHandler_impl(w, r) }
func adminAuthPasswordRecoveryHandler(w http.ResponseWriter, r *http.Request)      { adminAuthPasswordRecoveryHandler_impl(w, r) }
func adminAuthVerifyHandler(w http.ResponseWriter, r *http.Request)                { adminAuthVerifyHandler_impl(w, r) }
func adminAuthVerifyCodeURLHandler(w http.ResponseWriter, r *http.Request, code string) {
    adminAuthVerifyCodeURLHandler_impl(w, r, code)
}
func adminListHandler(w http.ResponseWriter, r *http.Request)                      { adminListHandler_impl(w, r) }
func adminCreateHandler(w http.ResponseWriter, r *http.Request)                    { adminCreateHandler_impl(w, r) }
func adminUpdateSubscriptionPlanHandler(w http.ResponseWriter, r *http.Request)    { adminUpdateSubscriptionPlanHandler_impl(w, r) }
func adminUpdateSystemRoleHandler(w http.ResponseWriter, r *http.Request)          { adminUpdateSystemRoleHandler_impl(w, r) }
func adminChangeOwnPasswordHandler(w http.ResponseWriter, r *http.Request)         { adminChangeOwnPasswordHandler_impl(w, r) }
func adminCreateAPITokenHandler(w http.ResponseWriter, r *http.Request)            { adminCreateAPITokenHandler_impl(w, r) }

// adminAuthVerificationCodeResendHandler reenvia (ou reutiliza) código de verificação para admin não verificado.
func adminAuthVerificationCodeResendHandler(w http.ResponseWriter, r *http.Request) {
    adminAuthVerificationCodeResendHandler_impl(w, r)
}

// Implementações (copiadas do httpapi.go)
func adminAuthTokenHandler_impl(w http.ResponseWriter, r *http.Request) {
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

func adminAuthRefreshHandler_impl(w http.ResponseWriter, r *http.Request) {
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

func adminAuthMFAVerifyHandler_impl(w http.ResponseWriter, r *http.Request) {
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

func adminAuthPasswordRecoveryHandler_impl(w http.ResponseWriter, r *http.Request) {
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
            "Message":          "Sua senha foi redefinida. Use a nova senha e o código para verificar sua conta.",
            "Event":            "admin_password_recovery",
            "Email":            req.Email,
            "Username":         username,
            "NewPassword":      newPass,
            "VerificationCode": code,
            "VerifyURL":        verifyURL,
            "Time":             time.Now().UTC().Format(time.RFC3339),
        }
        ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
        defer cancel()
        params := emailsvc.Params{To: []string{req.Email}, Subject: "Recuperação de senha e verificação", TemplateName: tmpl, Data: data}
        _ = mailer.Send(ctx, params)
    }
    // Sempre 200: evita enumeração.
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

func adminListHandler_impl(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet && r.Method != http.MethodHead {
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
            if n < 1 { n = 1 }
            if n > 100 { n = 100 }
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
            if v < actingPrio { allowed = append(allowed, k) }
        }
        if len(allowed) == 0 {
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "offset": offset, "limit": limit, "items": []any{}})
            return
        }
        // Monta placeholders e args
        ph := make([]string, len(allowed))
        args := make([]any, len(allowed))
        for i, r := range allowed { ph[i] = "?"; args[i] = r }
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

func adminCreateHandler_impl(w http.ResponseWriter, r *http.Request) {
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
        if passwordPolicyStrict() { req.Password = generateStrongPassword(12) } else { req.Password = generateNumericPassword(contants.DefaultGeneratedPasswordLength) }
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
    if actingID > 0 { ownerID = actingID }
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

    // Envia e-mail de criação (síncrono em serverless)
    if mailer != nil && !isTestEmail(req.Email) {
        verifyURL := buildVerifyURL(r, code)
        tmpl := cfg.AdminCreatedTemplate
        if strings.TrimSpace(tmpl) == "" { tmpl = cfg.EmailTemplateName }
        data := map[string]any{
            "Title":            "Sua conta de administrador",
            "Message":          "Use a senha e o código para verificar sua conta.",
            "Event":            "admin_created",
            "Email":            req.Email,
            "Username":         req.Username,
            "Password":         req.Password,
            "VerificationCode": code,
            "VerifyURL":        verifyURL,
            "Time":             time.Now().UTC().Format(time.RFC3339),
        }
        ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
        defer cancel()
        params := emailsvc.Params{To: []string{req.Email}, Subject: "Sua conta de administrador", TemplateName: tmpl, Data: data}
        if os.Getenv("VERCEL") != "" || os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
            _ = mailer.Send(ctx, params)
        } else {
            go func() { _ = mailer.Send(ctx, params) }()
        }
    }
    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "admin_id": newID, "email": req.Email, "username": req.Username})
}

func adminAuthVerifyHandler_impl(w http.ResponseWriter, r *http.Request) {
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

// adminAuthVerificationCodeResendHandler_impl: POST /admin/auth/verification-code
// Regras:
//  - Rate limit por IP e por login (usa VERIFY_RESEND_* ou herda RECOVERY_*)
//  - Reaproveita último código válido; se inexistente/expirado, gera novo e invalida anteriores
//  - Envia e-mail com link + código, exceto em e-mails de teste (@domain.com)
func adminAuthVerificationCodeResendHandler_impl(w http.ResponseWriter, r *http.Request) {
    // Throttle por IP e por login
    ip := clientIP(r)
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:adminverifyresend:ip:"+ip, int64(cfg.VerifyResendIPLimit), time.Duration(cfg.VerifyResendIPWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_IP", "message": "Muitas solicitações. Tente mais tarde."})
        return
    }
    var req struct{ Login string `json:"login"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Login) == "" {
        writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_014", "message": "login ausente"})
        return
    }
    login := strings.ToLower(strings.TrimSpace(req.Login))
    if ok, _, _ := kv.AllowRate(r.Context(), "rl:adminverifyresend:login:"+login, int64(cfg.VerifyResendLoginLimit), time.Duration(cfg.VerifyResendLoginWindowMinutes)*time.Minute); !ok {
        writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "code": "AUTH_429_EMAIL", "message": "Limite de reenvio excedido. Tente mais tarde."})
        return
    }

    // Busca admin
    var (
        adminID int64
        email   string
        username string
        verified bool
    )
    if err := sqldb.QueryRow(db.Rebind(`SELECT id, email, username, is_verified FROM admins WHERE username = ? OR email = ? LIMIT 1`), login, login).Scan(&adminID, &email, &username, &verified); err != nil {
        writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
        return
    }
    if verified { writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true}); return }

    // Reaproveita último código válido; senão, cria um novo e invalida anteriores
    var code string
    sel := db.Rebind(`SELECT code FROM admins_verifications 
        WHERE admin_id = ? AND consumed_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ORDER BY created_at DESC LIMIT 1`)
    if e := sqldb.QueryRow(sel, adminID).Scan(&code); e != nil || strings.TrimSpace(code) == "" {
        code, _ = generateVerificationCode(contants.VerificationCodeLength)
        _, _ = sqldb.Exec(db.Rebind(`INSERT INTO admins_verifications (admin_id, code, expires_at) VALUES (?,?,?)`), adminID, code, time.Now().Add(time.Duration(cfg.VerifyCodeTTLHours)*time.Hour))
        // Invalida anteriores não consumidos
        _, _ = sqldb.Exec(db.Rebind(`UPDATE admins_verifications SET consumed_at = CURRENT_TIMESTAMP WHERE admin_id = ? AND consumed_at IS NULL AND code <> ?`), adminID, code)
    }

    // Envia e-mail (pula e-mails de teste)
    if mailer != nil && !isTestEmail(email) {
        verifyURL := buildVerifyURL(r, code)
        tmpl := cfg.AdminCreatedTemplate
        if strings.TrimSpace(tmpl) == "" { tmpl = cfg.EmailTemplateName }
        data := map[string]any{
            "Title":            "Verificação de conta",
            "Message":          "Clique no botão abaixo ou use o código para verificar sua conta.",
            "Email":            email,
            "Username":         username,
            "VerificationCode": code,
            "VerifyURL":        verifyURL,
            // também suporta template genérico
            "ActionURL":        verifyURL,
            "ActionText":       "Verificar conta",
            "ExtraNote":        fmt.Sprintf("Seu código de verificação: %s", code),
        }
        ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
        defer cancel()
        _ = mailer.Send(ctx, emailsvc.Params{To: []string{email}, Subject: contants.EmailSubjectAdminCreated, TemplateName: tmpl, Data: data})
    }
    writeJSON(w, http.StatusOK, map[string]any{"success": true, "sent": true})
}

func adminUpdateSubscriptionPlanHandler_impl(w http.ResponseWriter, r *http.Request) {
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

func adminUpdateSystemRoleHandler_impl(w http.ResponseWriter, r *http.Request) {
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

func adminChangeOwnPasswordHandler_impl(w http.ResponseWriter, r *http.Request) {
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

func adminCreateAPITokenHandler_impl(w http.ResponseWriter, r *http.Request) {
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
        if exp.After(adminExpires.Time) { exp = adminExpires.Time }
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

func adminAuthVerifyCodeURLHandler_impl(w http.ResponseWriter, r *http.Request, code string) {
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
