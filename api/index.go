package handler // PACOTE OBRIGATÓRIO

import (
	"net/http"
	"sync"

	"github.com/gorilla/mux"

	"github.com/auth_fast_api/internal/auth"
	"github.com/auth_fast_api/internal/db"
	"github.com/auth_fast_api/internal/handlers"
)

// Inicialização única para garantir que o DB e o Roteador só sejam configurados uma vez
var (
	routerInstance *mux.Router
	once sync.Once
)

// setup: Configura todos os componentes da aplicação
func setup() {
	// 1. Inicializa o Banco de Dados (Postgres)
	db.InitDB() 
	
	// 2. Configura o roteador completo
	r := mux.NewRouter()

	// --- Rotas Públicas ---
	r.HandleFunc("/login", auth.LoginHandler).Methods("POST")
	
	// --- Rotas Protegidas ---
	s := r.PathPrefix("/api").Subrouter()
	s.Use(auth.JWTAuthMiddleware) // Aplica o middleware de autenticação

	// Handlers de Autorização
	s.HandleFunc("/api/users/list", handlers.ListUsersHandler).Methods("GET")
	s.HandleFunc("/api/resources/{id}", handlers.DeleteResourceHandler).Methods("DELETE")
	
	// Rota padrão (catch-all)
	s.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("API Base Route - Use /api/users/list"))
	})

	routerInstance = r
}

// Handler é o ponto de entrada principal para a Vercel.
func Handler(w http.ResponseWriter, r *http.Request) {
	// A instrução `once.Do` garante que a configuração ocorra APENAS na primeira vez
	// que a função Serverless é executada (o chamado "cold start").
	once.Do(setup)
	
	// O roteador trata a requisição
	routerInstance.ServeHTTP(w, r)
}