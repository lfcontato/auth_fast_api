package httpapi

import (
    "database/sql"
    "encoding/json"
    "net/http"
    "strconv"
    "strings"
    "time"
    db "github.com/lfcontato/auth_fast_api/internal/db"
)

// handleFaciendumRoutes roteia chamadas da tool Faciendum.
// Padrão: /user/spaces/{space_id}/faciendum/(boards|tracks|tasks[/{id}[/move]])
func handleFaciendumRoutes(w http.ResponseWriter, r *http.Request) bool {
    path := strings.Trim(r.URL.Path, "/")
    parts := strings.Split(path, "/")
    if len(parts) < 5 || parts[0] != "user" || parts[1] != "spaces" || parts[3] != "faciendum" {
        return false
    }
    // Aceita apenas hash do UsersSpace no segmento {space_id}
    var spaceID int64
    if err := sqldb.QueryRow(db.Rebind(`SELECT id FROM users_spaces WHERE hash = ? LIMIT 1`), parts[2]).Scan(&spaceID); err != nil || spaceID <= 0 {
        return false
    }
    userID, err := authenticateUser(r)
    if err != nil {
        writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "code": "AUTH_401_USER", "message": err.Error()})
        return true
    }
    if facdb == nil {
        writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "code": "FACIENDUM_503", "message": "Banco do Faciendum indisponível"})
        return true
    }
    resource := parts[4]
    var resourceID int64
    hasID := false
    if len(parts) >= 6 {
        if n, e := strconv.ParseInt(parts[5], 10, 64); e == nil && n > 0 { resourceID = n; hasID = true }
    }
    switch resource {
    case "boards":
        switch r.Method {
        case http.MethodGet:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            rows, err := facdb.Query(db.Rebind(`SELECT id, name, created_at, updated_at FROM faciendum_boards WHERE space_id = ? ORDER BY id DESC`), spaceID)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_LIST"}); return true }
            defer rows.Close()
            items := make([]map[string]any, 0)
            for rows.Next() {
                var id int64; var name string; var cAt, uAt time.Time
                _ = rows.Scan(&id, &name, &cAt, &uAt)
                items = append(items, map[string]any{"id": id, "name": name, "created_at": cAt, "updated_at": uAt})
            }
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
            return true
        case http.MethodPost:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            var req struct{ Name string `json:"name"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_BOARD", "message": "Nome é obrigatório"}); return true }
            tx, _ := facdb.Begin()
            res, err := tx.Exec(db.Rebind(`INSERT INTO faciendum_boards (space_id, name) VALUES (?, ?)`), spaceID, strings.TrimSpace(req.Name))
            if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_BOARD"}); return true }
            boardID, _ := res.LastInsertId()
            defaults := []struct{ name string; isFinal bool }{{"A Fazer", false}, {"Em Progresso", false}, {"Feito", true}}
            for i, t := range defaults {
                if _, err := tx.Exec(db.Rebind(`INSERT INTO faciendum_tracks (board_id, name, position, is_final) VALUES (?,?,?,?)`), boardID, t.name, i, t.isFinal); err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_TRACKS"}); return true }
            }
            if err := tx.Commit(); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_TX"}); return true }
            writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "board_id": boardID, "name": req.Name})
            return true
        case http.MethodPatch:
            if !hasID { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var req struct{ Name string `json:"name"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            var sID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), resourceID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            if _, err := facdb.Exec(db.Rebind(`UPDATE faciendum_boards SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`), strings.TrimSpace(req.Name), resourceID); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        case http.MethodDelete:
            if !hasID { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var sID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), resourceID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            tx, _ := facdb.Begin()
            _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tasks WHERE board_id = ?`), resourceID)
            _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tracks WHERE board_id = ?`), resourceID)
            res, err := tx.Exec(db.Rebind(`DELETE FROM faciendum_boards WHERE id = ?`), resourceID)
            if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            n, _ := res.RowsAffected(); if n == 0 { _ = tx.Rollback(); writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            _ = tx.Commit()
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        }
    case "tracks":
        switch r.Method {
        case http.MethodGet:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            boardIDStr := strings.TrimSpace(r.URL.Query().Get("board_id"))
            if boardIDStr == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_BOARD_ID"}); return true }
            bid, e := strconv.ParseInt(boardIDStr, 10, 64); if e != nil || bid <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            var sID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), bid).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            rows, err := facdb.Query(db.Rebind(`SELECT id, name, position, is_final, created_at, updated_at FROM faciendum_tracks WHERE board_id = ? ORDER BY position ASC, id ASC`), bid)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            defer rows.Close()
            items := make([]map[string]any, 0)
            for rows.Next() { var id int64; var name string; var pos int; var fin bool; var cAt, uAt time.Time; _ = rows.Scan(&id, &name, &pos, &fin, &cAt, &uAt); items = append(items, map[string]any{"id": id, "name": name, "position": pos, "is_final": fin, "created_at": cAt, "updated_at": uAt}) }
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "items": items})
            return true
        case http.MethodPost:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var req struct{ BoardID int64 `json:"board_id"`; Name string `json:"name"`; Position *int `json:"position"`; IsFinal *bool `json:"is_final"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BoardID <= 0 || strings.TrimSpace(req.Name) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            var sID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), req.BoardID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            var maxPos int
            _ = facdb.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tracks WHERE board_id = ?`), req.BoardID).Scan(&maxPos)
            targetPos := maxPos + 1
            if req.Position != nil && *req.Position >= 0 && *req.Position <= maxPos { targetPos = *req.Position }
            tx, _ := facdb.Begin()
            isFinal := false; if req.IsFinal != nil { isFinal = *req.IsFinal }
            if isFinal {
                targetPos = maxPos + 1
                _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET is_final = FALSE WHERE board_id = ?`), req.BoardID)
            } else {
                _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position + 1 WHERE board_id = ? AND position >= ?`), req.BoardID, targetPos)
            }
            res, err := tx.Exec(db.Rebind(`INSERT INTO faciendum_tracks (board_id, name, position, is_final) VALUES (?,?,?,?)`), req.BoardID, strings.TrimSpace(req.Name), targetPos, isFinal)
            if err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            tid, _ := res.LastInsertId(); _ = tx.Commit()
            writeJSON(w, http.StatusCreated, map[string]any{"success": true, "track_id": tid, "position": targetPos, "is_final": isFinal})
            return true
        case http.MethodPatch:
            if !hasID { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var req struct{ Name *string `json:"name"`; Position *int `json:"position"`; IsFinal *bool `json:"is_final"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            var boardID int64; var oldPos int; var wasFinal bool
            if err := facdb.QueryRow(db.Rebind(`SELECT board_id, position, is_final FROM faciendum_tracks WHERE id = ?`), resourceID).Scan(&boardID, &oldPos, &wasFinal); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            var sID int64; if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_boards WHERE id = ?`), boardID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            tx, _ := facdb.Begin()
            if req.Name != nil { _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET name = ? WHERE id = ?`), strings.TrimSpace(*req.Name), resourceID) }
            if req.IsFinal != nil {
                if *req.IsFinal {
                    var maxPos int; _ = tx.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tracks WHERE board_id = ?`), boardID).Scan(&maxPos)
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET is_final = FALSE WHERE board_id = ?`), boardID)
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position - 1 WHERE board_id = ? AND position > ?`), boardID, oldPos)
                    oldPos = maxPos
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = ? , is_final = TRUE WHERE id = ?`), maxPos, resourceID)
                } else {
                    _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET is_final = FALSE WHERE id = ?`), resourceID)
                }
            }
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
            if err := tx.Commit(); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        case http.MethodDelete:
            if !hasID { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionBoardWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var boardID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT board_id FROM faciendum_tracks WHERE id = ?`), resourceID).Scan(&boardID); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            var cnt int; _ = facdb.QueryRow(db.Rebind(`SELECT COUNT(1) FROM faciendum_tasks WHERE track_id = ?`), resourceID).Scan(&cnt)
            if cnt > 0 { writeJSON(w, http.StatusConflict, map[string]any{"success": false, "code": "FACIENDUM_409_TRACK_NOT_EMPTY"}); return true }
            var pos int; _ = facdb.QueryRow(db.Rebind(`SELECT position FROM faciendum_tracks WHERE id = ?`), resourceID).Scan(&pos)
            tx, _ := facdb.Begin()
            _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tracks WHERE id = ?`), resourceID)
            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tracks SET position = position - 1 WHERE board_id = ? AND position > ?`), boardID, pos)
            _ = tx.Commit()
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        }
    case "tasks":
        switch r.Method {
        case http.MethodGet:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskRead); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            boardIDStr := r.URL.Query().Get("board_id")
            q := `SELECT id, board_id, track_id, title, description, position, created_at, updated_at FROM faciendum_tasks WHERE space_id = ?`
            args := []any{spaceID}
            if b := strings.TrimSpace(boardIDStr); b != "" {
                if bid, err := strconv.ParseInt(b, 10, 64); err == nil && bid > 0 { q += ` AND board_id = ?`; args = append(args, bid) }
            }
            q += ` ORDER BY board_id, position, id`
            rows, err := facdb.Query(db.Rebind(q), args...)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_LIST_TASKS"}); return true }
            defer rows.Close()
            items := make([]map[string]any, 0)
            for rows.Next() {
                var id, bid, tid int64; var title, desc sql.NullString; var pos int; var cAt, uAt time.Time
                _ = rows.Scan(&id, &bid, &tid, &title, &desc, &pos, &cAt, &uAt)
                items = append(items, map[string]any{"id": id, "board_id": bid, "track_id": tid, "title": title.String, "description": desc.String, "position": pos, "created_at": cAt, "updated_at": uAt})
            }
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "space_id": spaceID, "items": items})
            return true
        case http.MethodPost:
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "code": "AUTH_403_ACL"}); return true }
            var req struct{ BoardID int64 `json:"board_id"`; Title string `json:"title"`; Description string `json:"description"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BoardID <= 0 || strings.TrimSpace(req.Title) == "" { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_TASK", "message": "board_id e title são obrigatórios"}); return true }
            var firstTrackID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT id FROM faciendum_tracks WHERE board_id = ? ORDER BY position ASC LIMIT 1`), req.BoardID).Scan(&firstTrackID); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_TRACK", "message": "Board inválido ou sem trilhas"}); return true }
            res, err := facdb.Exec(db.Rebind(`INSERT INTO faciendum_tasks (space_id, board_id, track_id, title, description, position) VALUES (?,?,?,?,?,?)`), spaceID, req.BoardID, firstTrackID, strings.TrimSpace(req.Title), strings.TrimSpace(req.Description), 0)
            if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "FACIENDUM_500_TASK"}); return true }
            taskID, _ := res.LastInsertId()
            writeJSON(w, http.StatusCreated, map[string]any{"success": true, "space_id": spaceID, "task_id": taskID})
            return true
        case http.MethodPatch:
            if !hasID { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var req struct{ Title *string `json:"title"`; Description *string `json:"description"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            var sID int64; if err := facdb.QueryRow(db.Rebind(`SELECT space_id FROM faciendum_tasks WHERE id = ?`), resourceID).Scan(&sID); err != nil || sID != spaceID { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            if req.Title == nil && req.Description == nil { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            if req.Title != nil { _, _ = facdb.Exec(db.Rebind(`UPDATE faciendum_tasks SET title = ? WHERE id = ?`), strings.TrimSpace(*req.Title), resourceID) }
            if req.Description != nil { _, _ = facdb.Exec(db.Rebind(`UPDATE faciendum_tasks SET description = ? WHERE id = ?`), strings.TrimSpace(*req.Description), resourceID) }
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        case http.MethodDelete:
            if !hasID { return false }
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var trackID int64; var pos int
            if err := facdb.QueryRow(db.Rebind(`SELECT track_id, position FROM faciendum_tasks WHERE id = ? AND space_id = ?`), resourceID, spaceID).Scan(&trackID, &pos); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            tx, _ := facdb.Begin()
            _, _ = tx.Exec(db.Rebind(`DELETE FROM faciendum_tasks WHERE id = ?`), resourceID)
            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET position = position - 1 WHERE track_id = ? AND position > ?`), trackID, pos)
            _ = tx.Commit()
            writeJSON(w, http.StatusOK, map[string]any{"success": true})
            return true
        }
        // Move
        if hasID && len(parts) >= 7 && parts[6] == "move" && (r.Method == http.MethodPatch || r.Method == http.MethodPost) {
            if err := requireSpacePermission(r.Context(), userID, spaceID, actionTaskWrite); err != nil { writeJSON(w, http.StatusForbidden, map[string]any{"success": false}); return true }
            var req struct{ ToTrackID int64 `json:"to_track_id"`; Position *int `json:"position"` }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ToTrackID <= 0 { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false}); return true }
            var curTrackID, curBoardID int64; var curPos int
            if err := facdb.QueryRow(db.Rebind(`SELECT track_id, board_id, position FROM faciendum_tasks WHERE id = ? AND space_id = ?`), resourceID, spaceID).Scan(&curTrackID, &curBoardID, &curPos); err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"success": false}); return true }
            var destBoardID int64
            if err := facdb.QueryRow(db.Rebind(`SELECT board_id FROM faciendum_tracks WHERE id = ?`), req.ToTrackID).Scan(&destBoardID); err != nil || destBoardID != curBoardID { writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "FACIENDUM_400_MOVE_DEST"}); return true }
            tx, _ := facdb.Begin()
            _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET position = position - 1 WHERE track_id = ? AND position > ?`), curTrackID, curPos)
            var maxPos int; _ = tx.QueryRow(db.Rebind(`SELECT COALESCE(MAX(position), -1) FROM faciendum_tasks WHERE track_id = ?`), req.ToTrackID).Scan(&maxPos)
            newPos := maxPos + 1
            if req.Position != nil && *req.Position >= 0 && *req.Position <= maxPos {
                newPos = *req.Position
                _, _ = tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET position = position + 1 WHERE track_id = ? AND position >= ?`), req.ToTrackID, newPos)
            }
            if _, err := tx.Exec(db.Rebind(`UPDATE faciendum_tasks SET track_id = ?, position = ? WHERE id = ?`), req.ToTrackID, newPos, resourceID); err != nil { _ = tx.Rollback(); writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false}); return true }
            _ = tx.Commit()
            writeJSON(w, http.StatusOK, map[string]any{"success": true, "position": newPos, "track_id": req.ToTrackID})
            return true
        }
    }
    return false
}
