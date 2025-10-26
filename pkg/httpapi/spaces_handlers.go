package httpapi

import (
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "time"

    "github.com/lfcontato/auth_fast_api/internal/db"
    "github.com/lfcontato/auth_fast_api/internal/contants"
)

func isValidMemberRole(role string) bool {
    switch strings.ToLower(strings.TrimSpace(role)) {
    case "admin", "user", "guest":
        return true
    }
    return false
}

// userSpacesCreateHandler: POST /user/spaces (somente usuário com tools_role=admin)
func userSpacesCreateHandler(w http.ResponseWriter, r *http.Request) {
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
func userSpacesListHandler(w http.ResponseWriter, r *http.Request) {
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

// Membros do espaço
func userSpacesMembersAddHandler(w http.ResponseWriter, r *http.Request) {
    userID, err := authenticateUser(r)
    if err != nil { writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()}); return }
    parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
    if len(parts) < 4 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "HTTP_404"}); return }
    spaceID, e := strconv.ParseInt(parts[2], 10, 64)
    if e != nil || spaceID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_SPACE_ID"}); return }
    var ownerID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT owner_user_id FROM users_spaces WHERE id = ? LIMIT 1`), spaceID).Scan(&ownerID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "code": "AUTH_404_SPACE"}); return }
    if ownerID != userID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_SPACE", "message": "Apenas o proprietário pode gerenciar membros"}); return }
    var req struct{ Login string `json:"login"`; Role string `json:"role"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Login) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_MEMBER", "message": "login/role inválidos"}); return }
    role := strings.ToLower(strings.TrimSpace(req.Role))
    if role == "" { role = "guest" }
    if !isValidMemberRole(role) { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_ROLE"}); return }
    login := strings.ToLower(strings.TrimSpace(req.Login))
    var targetID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1`), login, login).Scan(&targetID); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_USER_NOT_FOUND"}); return }
    if targetID == ownerID { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTH_400_OWNER", "message": "Proprietário não é membro gerenciável"}); return }
    res, err := sqldb.Exec(db.Rebind(`INSERT INTO users_spaces_members (space_id, user_id, role) VALUES (?,?,?)`), spaceID, targetID, role)
    if err != nil { writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "AUTH_409_MEMBER"}); return }
    mid, _ := res.LastInsertId()
    writeJSON(w, http.StatusCreated, map[string]any{"success": true, "member_id": mid, "space_id": spaceID, "user_id": targetID, "role": role})
}

func userSpacesMembersListHandler(w http.ResponseWriter, r *http.Request) {
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

func userSpacesMembersUpdateRoleHandler(w http.ResponseWriter, r *http.Request) {
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

func userSpacesMembersRemoveHandler(w http.ResponseWriter, r *http.Request) {
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
