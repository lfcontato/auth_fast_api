package httpapi

import (
    "net/http"
    "strings"
)

// handleUserSpacesRoutes roteia chamadas relacionadas a UsersSpaces e membership.
// Retorna true quando a rota foi atendida.
func handleUserSpacesRoutes(w http.ResponseWriter, r *http.Request) bool {
    path := r.URL.Path
    switch {
    case path == "/user/spaces" && r.Method == http.MethodPost:
        spacesHandleCreate(w, r); return true
    case path == "/user/spaces" && r.Method == http.MethodGet:
        spacesHandleList(w, r); return true
    case strings.HasPrefix(path, "/user/spaces/") && strings.HasSuffix(path, "/members") && r.Method == http.MethodPost:
        spacesHandleMembersAdd(w, r); return true
    case strings.HasPrefix(path, "/user/spaces/") && strings.HasSuffix(path, "/members") && r.Method == http.MethodGet:
        spacesHandleMembersList(w, r); return true
    case strings.HasPrefix(path, "/user/spaces/") && strings.Contains(path, "/members/") && r.Method == http.MethodPatch:
        spacesHandleMembersUpdate(w, r); return true
    case strings.HasPrefix(path, "/user/spaces/") && strings.Contains(path, "/members/") && r.Method == http.MethodDelete:
        spacesHandleMembersRemove(w, r); return true
    }
    return false
}
