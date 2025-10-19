// Caminho: api/index.go
// Resumo: Wrapper para Vercel. Usa package handler e delega para pkg/httpapi.

package handler

import (
	httpapi "github.com/lfcontato/auth_fast_api/pkg/httpapi"
	"net/http"
)

// Handler é o entrypoint exigido pelo runtime Go da Vercel.
func Handler(w http.ResponseWriter, r *http.Request) {
	httpapi.Handler(w, r)
}
