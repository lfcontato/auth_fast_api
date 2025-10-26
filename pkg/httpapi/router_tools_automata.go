package httpapi

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "strings"
    "time"
    db "github.com/lfcontato/auth_fast_api/internal/db"
)

// handleAutomataRoutes roteia chamadas da tool Automata.
// Padrão: /user/spaces/{space_id}/automata/(keys|prompts|chats[/{id}])
func handleAutomataRoutes(w http.ResponseWriter, r *http.Request) bool {
    path := strings.Trim(r.URL.Path, "/")
    parts := strings.Split(path, "/")
    if len(parts) < 5 || parts[0] != "user" || parts[1] != "spaces" || parts[3] != "automata" {
        return false
    }
    spaceID, err := strconv.ParseInt(parts[2], 10, 64)
    if err != nil || spaceID <= 0 { return false }
    userID, err := authenticateUser(r)
    if err != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()})
        return true
    }
    if autdb == nil {
        writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "AUTOMATA_503", "message": "Banco do Automata indisponível"})
        return true
    }
    resource := parts[4]
    var itemID int64
    if len(parts) >= 6 { if n, e := strconv.ParseInt(parts[5], 10, 64); e == nil && n > 0 { itemID = n } }

    switch resource {
    case "keys":
        switch r.Method {
        case http.MethodGet:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            rows, err := autdb.Query(db.Rebind(`SELECT id, provider, name, created_at FROM automata_api_keys WHERE user_id = ? ORDER BY id DESC`), userID)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            defer rows.Close()
            items := make([]map[string]any, 0)
            for rows.Next() { var id int64; var provider, name string; var cAt time.Time; _ = rows.Scan(&id, &provider, &name, &cAt); items = append(items, map[string]any{"id": id, "provider": provider, "name": name, "created_at": cAt}) }
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
            return true
        case http.MethodPost:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            var req struct{ Provider, Name, ApiKey string }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Provider) == "" || strings.TrimSpace(req.ApiKey) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_KEY", "message": "provider e api_key são obrigatórios"}); return true }
            res, err := autdb.Exec(db.Rebind(`INSERT INTO automata_api_keys (user_id, provider, name, api_key) VALUES (?,?,?,?)`), userID, strings.TrimSpace(req.Provider), strings.TrimSpace(req.Name), strings.TrimSpace(req.ApiKey))
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            kid, _ := res.LastInsertId()
            writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "api_key_id": kid})
            return true
        case http.MethodDelete:
            if itemID <= 0 { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            res, err := autdb.Exec(db.Rebind(`DELETE FROM automata_api_keys WHERE id = ? AND user_id = ?`), itemID, userID)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            n, _ := res.RowsAffected(); if n == 0 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        }
    case "prompts":
        switch r.Method {
        case http.MethodGet:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            rows, err := autdb.Query(db.Rebind(`SELECT id, name, description, provider, api_key_id, created_at FROM automata_prompts WHERE user_id = ? ORDER BY id DESC`), userID)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            defer rows.Close()
            items := make([]map[string]any, 0)
            for rows.Next() { var id int64; var name, desc, provider sql.NullString; var keyID sql.NullInt64; var cAt time.Time; _ = rows.Scan(&id, &name, &desc, &provider, &keyID, &cAt); items = append(items, map[string]any{"id": id, "name": name.String, "description": desc.String, "provider": provider.String, "api_key_id": keyID.Int64, "created_at": cAt}) }
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
            return true
        case http.MethodPost:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            var req struct{ Name, Description, Provider string; ApiKeyID int64 }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_PROMPT", "message": "name é obrigatório"}); return true }
            if req.ApiKeyID > 0 {
                var exists int
                if err := autdb.QueryRow(db.Rebind(`SELECT 1 FROM automata_api_keys WHERE id = ? AND user_id = ?`), req.ApiKeyID, userID).Scan(&exists); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_KEY_REF", "message": "api_key_id inválido"}); return true }
            }
            res, err := autdb.Exec(db.Rebind(`INSERT INTO automata_prompts (user_id, api_key_id, provider, name, description) VALUES (?,?,?,?,?)`), userID, nullIfZero(req.ApiKeyID), nullIfEmpty(req.Provider), strings.TrimSpace(req.Name), strings.TrimSpace(req.Description))
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            pid, _ := res.LastInsertId()
            writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "prompt_id": pid})
            return true
        case http.MethodPatch:
            if itemID <= 0 { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var req struct{ Name, Description, Provider string; ApiKeyID int64 }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            if req.ApiKeyID > 0 {
                var exists int
                if err := autdb.QueryRow(db.Rebind(`SELECT 1 FROM automata_api_keys WHERE id = ? AND user_id = ?`), req.ApiKeyID, userID).Scan(&exists); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            }
            if _, err := autdb.Exec(db.Rebind(`UPDATE automata_prompts SET name = COALESCE(NULLIF(?, ''), name), description = COALESCE(?, description), provider = COALESCE(NULLIF(?, ''), provider), api_key_id = COALESCE(?, api_key_id), updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`), strings.TrimSpace(req.Name), nullIfEmpty(req.Description), nullIfEmpty(req.Provider), nullIfZero(req.ApiKeyID), itemID, userID); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        case http.MethodDelete:
            if itemID <= 0 { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            res, err := autdb.Exec(db.Rebind(`DELETE FROM automata_prompts WHERE id = ? AND user_id = ?`), itemID, userID)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            n, _ := res.RowsAffected(); if n == 0 { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        }
    case "chats":
        switch r.Method {
        case http.MethodGet:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            rows, err := autdb.Query(db.Rebind(`SELECT id, prompt_id, message, response, created_at FROM automata_chats WHERE space_id = ? AND user_id = ? ORDER BY id DESC`), spaceID, userID)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            defer rows.Close()
            items := make([]map[string]any, 0)
            for rows.Next() { var id, pid int64; var msg string; var resp sql.NullString; var cAt time.Time; _ = rows.Scan(&id, &pid, &msg, &resp, &cAt); items = append(items, map[string]any{"id": id, "prompt_id": pid, "message": msg, "response": resp.String, "created_at": cAt}) }
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
            return true
        case http.MethodPost:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionSpaceWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            var req struct{ PromptID int64; Message string }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PromptID <= 0 || strings.TrimSpace(req.Message) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "AUTOMATA_400_CHAT", "message": "prompt_id e message são obrigatórios"}); return true }
            var owner int64
            if err := autdb.QueryRow(db.Rebind(`SELECT user_id FROM automata_prompts WHERE id = ? LIMIT 1`), req.PromptID).Scan(&owner); err != nil || owner != userID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTOMATA_403_PROMPT"}); return true }
            resp := fmt.Sprintf("[automata] %s", strings.TrimSpace(req.Message))
            res, err := autdb.Exec(db.Rebind(`INSERT INTO automata_chats (space_id, user_id, prompt_id, message, response) VALUES (?,?,?,?,?)`), spaceID, userID, req.PromptID, strings.TrimSpace(req.Message), resp)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            cid, _ := res.LastInsertId()
            writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "chat_id": cid, "response": resp})
            return true
        }
    }
    return false
}
