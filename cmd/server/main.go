// Caminho: cmd/server/main.go
// Resumo: Servidor HTTP local para desenvolvimento. Encapsula o handler serverless (api/index.go)
// e expõe a API em localhost:8080.

package main

import (
	"log"
	"net/http"

	"github.com/lfcontato/auth_fast_api/pkg/httpapi"
)

// main inicia um servidor HTTP local e encaminha todas as rotas para o handler da API.
func main() {
	http.HandleFunc("/", httpapi.Handler)
	addr := ":8080"
	log.Printf("API iniciada em http://localhost%v", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
