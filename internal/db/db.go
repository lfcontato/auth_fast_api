package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

// DB é a instância global do banco de dados para ser usada em toda a aplicação.
var DB *sql.DB

// Modelos
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // Esconde a senha no JSON
	Role     string `json:"role"`
}

type Resource struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	OwnerID int `json:"owner_id"`
}

// InitDB inicializa a conexão com o PostgreSQL.
func InitDB() {
	// IMPORTANTE: Use variáveis de ambiente na Vercel para a string de conexão real
	// Este valor é um placeholder!
	connStr := "user=seu_usuario password=sua_senha dbname=seu_db sslmode=disable"
	var err error
	
	// Verifica se a conexão já foi estabelecida (importante para Serverless Functions)
	if DB != nil {
		return 
	}
	
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Erro ao abrir conexão com DB:", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal("Erro ao conectar ao DB:", err)
	}

	fmt.Println("Conexão com PostgreSQL estabelecida com sucesso!")
	createTables()
	seedData()
}

// Funções createTables e seedData (Mantidas como no exemplo anterior)
func createTables() { /* ... implementação ... */ }
func seedData() { /* ... implementação ... */ }