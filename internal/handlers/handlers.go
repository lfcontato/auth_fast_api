package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/auth_fast_api/internal/auth" // Importa o pacote Auth
	"github.com/auth_fast_api/internal/db"   // Importa o pacote DB
)

// GetClaims extrai as Claims do contexto da requisição
func GetClaims(r *http.Request) (*auth.Claims, bool) {
	claims, ok := r.Context().Value("userClaims").(*auth.Claims)
	return claims, ok
}

// HasRole e IsOwner (Lógica de autorização simplificada)
func HasRole(r *http.Request, requiredRole string) bool {
	// ... (Implementação usando GetClaims)
	return true // Simplificado
}
func IsRoot(r *http.Request) bool {
	// ... (Implementação usando GetClaims)
	return true // Simplificado
}

// ListUsersHandler (RBAC)
func ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Autorização: Apenas 'root' e 'admin'
	claims, ok := GetClaims(r)
	if !ok || (claims.Role != "root" && claims.Role != "admin") {
		http.Error(w, "Acesso negado: RBAC falhou.", http.StatusForbidden)
		return
	}
	
	// 2. Execução (Usando db.DB)
	// ... (Lógica de buscar usuários)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Lista de usuários (RBAC OK)"})
}

// DeleteResourceHandler (PBAC/ABAC)
func DeleteResourceHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := GetClaims(r)
	if !ok {
		http.Error(w, "Não autorizado", http.StatusUnauthorized)
		return
	}
	
	vars := mux.Vars(r)
	resourceID := vars["id"]
	resourceOwnerID := 100 // Simula a busca no DB

	// PBAC SIMULADO: (user.role == 'root') || (user.id == resource.owner_id)
	if claims.Role == "root" || claims.UserID == resourceOwnerID {
		// Autorizado!
		fmt.Fprintf(w, "Recurso %s deletado. Autorização: PBAC/ABAC OK.", resourceID)
		return
	}

	http.Error(w, "Acesso negado: PBAC/ABAC falhou.", http.StatusForbidden)
}