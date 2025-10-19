Arquivo: tests/README.md
Resumo: Como usar os arquivos .http (VS Code REST Client) para testar a API local.

Pré-requisitos
- Extensão "REST Client" no VS Code (humao.rest-client)
- API rodando localmente em http://localhost:8080 (use `go run ./cmd/server`)

Arquivos de teste
- tests/health.http: verifica `/healthz`.
- tests/auth.http: executa login com `ROOT_AUTH_*` do `.env` e faz refresh usando o refresh_token retornado.

Variáveis
- Os arquivos utilizam `{{$dotenv ...}}` para ler `ROOT_AUTH_USER` e `ROOT_AUTH_PASSWORD` do seu `.env` na raiz do projeto.

Como usar
1) Inicie a API: `go run ./cmd/server`
2) Abra o arquivo desejado (`tests/auth.http` ou `tests/health.http`) no VS Code
3) Clique em "Send Request" acima de cada requisição
4) Para o fluxo de auth: rode primeiro `@login`, depois `@refresh` (ele referencia o `refresh_token` do login automaticamente).

