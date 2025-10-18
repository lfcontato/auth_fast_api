package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/auth_fast_api/internal/db" // Importa o pacote DB
)

// Chave secreta para assinar o JWT
var jwtKey = []byte("super_secreta_e_forte_chave")

// Claims personalizados
type Claims struct {
	UserID int `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

// Gerador de Token
func GenerateToken(user *db.User) (string, error) {
	// ... (Implementação mantida)
}

// Middleware de Autenticação JWT
func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ... (Implementação de verificação de token mantida)
		// ... (Armazena claims no contexto)
		
		// Trecho simplificado da lógica de Claims:
		claims := &Claims{UserID: 1, Role: "root"} // Simplificado para exemplo

		ctx := context.WithValue(r.Context(), "userClaims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handler de Login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// ... (Implementação de login usando db.DB)
}