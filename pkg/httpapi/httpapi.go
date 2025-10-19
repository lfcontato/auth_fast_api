// Caminho: pkg/httpapi/httpapi.go
// Resumo: Ponto de entrada HTTP compartilhado entre Vercel e servidor local, com todas as rotas da API.

package httpapi

import (
    "context"
    crand "crypto/rand"
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
		"endpoints": []string{"/healthz", "/admin/auth/token", "/admin/auth/token/refresh", "/admin/auth/password-recovery", "/admin (GET)"},
	})
}

// adminAuthTokenHandler é um stub do endpoint de login /admin/auth/token.
// Por enquanto retorna 501 (Not Implemented) até integração com serviços de autenticação.
func adminAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
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
func adminAuthRefreshHandler(w http.ResponseWriter, r *http.Request) {
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
func adminAuthMFAVerifyHandler(w http.ResponseWriter, r *http.Request) {
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

// adminAuthPasswordRecoveryHandler permite a recuperação de senha sem autenticação.
// Recebe um e-mail, gera uma nova senha e um novo código de verificação e os envia por e-mail.
func adminAuthPasswordRecoveryHandler(w http.ResponseWriter, r *http.Request) {
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
func adminListHandler(w http.ResponseWriter, r *http.Request) {
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
func adminCreateHandler(w http.ResponseWriter, r *http.Request) {
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
func adminAuthVerifyHandler(w http.ResponseWriter, r *http.Request) {
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
func adminUpdateSubscriptionPlanHandler(w http.ResponseWriter, r *http.Request) {
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
func adminUpdateSystemRoleHandler(w http.ResponseWriter, r *http.Request) {
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
func adminChangeOwnPasswordHandler(w http.ResponseWriter, r *http.Request) {
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

// adminAuthVerifyCodeURLHandler confirma a conta recebendo o código na URL e senha no corpo.
func adminAuthVerifyCodeURLHandler(w http.ResponseWriter, r *http.Request, code string) {
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

	switch {
	case path == "/" || path == "":
		rootHandler(w, r)
		return

	case path == "/healthz":
		healthHandler(w, r)
		return

	case path == "/admin/auth/token" && r.Method == http.MethodPost:
		adminAuthTokenHandler(w, r)
		return

    case path == "/admin/auth/token/refresh" && r.Method == http.MethodPost:
        adminAuthRefreshHandler(w, r)
        return

    case path == "/admin/auth/mfa/verify" && r.Method == http.MethodPost:
        adminAuthMFAVerifyHandler(w, r)
        return

	case path == "/admin/auth/password-recovery" && r.Method == http.MethodPost:
		adminAuthPasswordRecoveryHandler(w, r)
		return

	case strings.HasPrefix(path, "/admin/auth/verify-code/") && r.Method == http.MethodPost:
		code := strings.TrimPrefix(path, "/admin/auth/verify-code/")
		adminAuthVerifyCodeURLHandler(w, r, code)
		return

	case path == "/admin/auth/verify" && r.Method == http.MethodPost:
		adminAuthVerifyHandler(w, r)
		return

	case (path == "/admin" || path == "/admin/") && r.Method == http.MethodPost:
		adminCreateHandler(w, r)
		return

    case (path == "/admin" || path == "/admin/") && r.Method == http.MethodGet:
        adminListHandler(w, r)
        return

    case strings.HasPrefix(path, "/admin/") && strings.HasSuffix(path, "/subscription-plan") && r.Method == http.MethodPatch:
        adminUpdateSubscriptionPlanHandler(w, r)
        return

    case strings.HasPrefix(path, "/admin/") && strings.HasSuffix(path, "/system-role") && r.Method == http.MethodPatch:
        adminUpdateSystemRoleHandler(w, r)
        return

    case path == "/admin/password" && r.Method == http.MethodPatch:
        adminChangeOwnPasswordHandler(w, r)
        return

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
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("algoritmo inválido")
		}
		return []byte(cfg.SecretKey), nil
	})
	if err != nil || !tok.Valid {
		return 0, "", errors.New("token inválido")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return 0, "", errors.New("claims inválidas")
	}
	sub, _ := claims["sub"].(string)
	sro, _ := claims["sro"].(string)
	if sub == "" || sro == "" {
		return 0, "", errors.New("claims incompletas")
	}
	var id int64 = 0
	if strings.HasPrefix(sub, "admin|") {
		// extrai ID após prefixo
		parts := strings.SplitN(sub, "|", 2)
		if len(parts) == 2 {
			if n, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				id = n
			}
		}
	}
	// Verifica no banco se a conta está verificada (is_verified = 1)
	if id > 0 {
		var verified bool
		if err := sqldb.QueryRow(db.Rebind(`SELECT is_verified FROM admins WHERE id = ? LIMIT 1`), id).Scan(&verified); err != nil {
			return 0, "", errors.New("conta inexistente")
		}
		if !verified {
			return 0, "", errors.New("conta não verificada")
		}
	}
	return id, sro, nil
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
