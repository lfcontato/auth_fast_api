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
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/lfcontato/auth_fast_api/internal/config"
	"github.com/lfcontato/auth_fast_api/internal/contants"
	"github.com/lfcontato/auth_fast_api/internal/db"
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
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_001", "message": "JSON inválido"})
		return
	}
	access, refresh, err := service.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		logWarn("login failed for '%s': %v", req.Username, err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_001", "message": err.Error()})
		return
	}
	logInfo("login success for '%s'", req.Username)
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

// adminAuthPasswordRecoveryHandler permite a recuperação de senha sem autenticação.
// Recebe um e-mail, gera uma nova senha e um novo código de verificação e os envia por e-mail.
func adminAuthPasswordRecoveryHandler(w http.ResponseWriter, r *http.Request) {
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

	// Gera nova senha e atualiza hash
	newPass := generateNumericPassword(contants.DefaultGeneratedPasswordLength)
	if newPass == "" {
		newPass = generateNumericPassword(8)
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
	if _, err := tx.Exec(db.Rebind(`INSERT INTO admins_verifications (admin_id, code) VALUES (?, ?)`), adminID, code); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_012", "message": "Falha ao criar código de verificação"})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "AUTH_500_013", "message": "Falha ao confirmar recuperação"})
		return
	}

	// Envia e-mail com nova senha e código
	if mailer != nil {
		verifyURL := buildVerifyURL(r, code)
		go func(email, username, pass, code, verifyURL string) {
			tmpl := cfg.AdminCreatedTemplate
			if strings.TrimSpace(tmpl) == "" {
				tmpl = cfg.EmailTemplateName
			}
			data := map[string]any{
				"Title":            "Recuperação de senha",
				"Message":          "Sua senha foi redefinida. Use a nova senha e o código abaixo para verificar sua conta.",
				"Email":            email,
				"Username":         username,
				"Password":         pass,
				"VerificationCode": code,
				"VerifyURL":        verifyURL,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := mailer.Send(ctx, emailsvc.Params{
				To:           []string{email},
				Subject:      contants.EmailSubjectPasswordRecovery,
				TemplateName: tmpl,
				Data:         data,
			}); err != nil {
				logWarn("send email password recovery: %v", err)
			}
		}(req.Email, username, newPass, code, verifyURL)
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
		Email      string `json:"email"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		SystemRole string `json:"system_role"`
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
	// Senha opcional: gera automaticamente se vazia. Caso informada, valida tamanho mínimo.
	req.Password = strings.TrimSpace(req.Password)
	if req.Password == "" {
		req.Password = generateNumericPassword(contants.DefaultGeneratedPasswordLength)
	} else if len(req.Password) < contants.DefaultGeneratedPasswordLength {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_005", "message": "Senha deve ter pelo menos 8 caracteres"})
		return
	}
	if !canManageSystemRole(actingRole, req.SystemRole) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_001", "message": "Papel insuficiente para criar este administrador"})
		return
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
		q := db.Rebind(`INSERT INTO admins (email, username, password_hash, system_role, is_verified, owner_id) VALUES (?,?,?,?,?,?) RETURNING id`)
		if err := sqldb.QueryRow(q, req.Email, req.Username, string(hash), req.SystemRole, false, ownerID).Scan(&newID); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_001", "message": "Email ou username já existente"})
			return
		}
	} else {
		res, err := sqldb.Exec(db.Rebind(`INSERT INTO admins (email, username, password_hash, system_role, is_verified, owner_id) VALUES (?,?,?,?,?,?)`), req.Email, req.Username, string(hash), req.SystemRole, false, ownerID)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_001", "message": "Email ou username já existente"})
			return
		}
		newID, _ = res.LastInsertId()
	}

	// Gera código de verificação único e persiste
	code, err := generateVerificationCode(contants.VerificationCodeLength)
	if err == nil {
		if _, e := sqldb.Exec(db.Rebind(`INSERT INTO admins_verifications (admin_id, code) VALUES (?,?)`), newID, code); e != nil {
			logWarn("save verification code failed: %v", e)
		}
	} else {
		logWarn("generate verification code failed: %v", err)
		code = ""
	}

	// Envia e-mail de criação
	if mailer != nil {
		go func() {
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
			if err := mailer.Send(ctx, emailsvc.Params{
				To:           []string{req.Email},
				Subject:      contants.EmailSubjectAdminCreated,
				TemplateName: tmpl,
				Data:         data,
			}); err != nil {
				logWarn("send email admin created: %v", err)
			}
		}()
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"success":     true,
		"admin_id":    newID,
		"username":    req.Username,
		"email":       req.Email,
		"system_role": req.SystemRole,
	})
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
        WHERE v.code = ? AND v.consumed_at IS NULL
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
        WHERE v.code = ? AND v.consumed_at IS NULL
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
	// Request logging (método, caminho, status, duração)
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	defer func() {
		dur := time.Since(start)
		logInfo("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, dur.String())
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
	if dbURL == "" {
		dbURL = cfg.DatabaseURL
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
		// create verified root user
		if _, e := sqldb.Exec(db.Rebind(`INSERT INTO admins (email, username, password_hash, system_role, is_verified) VALUES (?,?,?,?,?)`), email, user, string(hash), "root", true); e != nil {
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
