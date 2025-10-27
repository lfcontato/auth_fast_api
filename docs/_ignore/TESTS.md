Arquivo: docs/TESTS.md
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

## Fluxo de testes (Vercel)

# 1) Criar usuário
curl -X POST http://localhost:8080/api/user \
  -H 'Content-Type: application/json' \
  -d '{ "email":"luis.fernando.pereira.procempa@gmail.com", "username":"lfcontato", "password":"MinhaSenha123!", "confirm_password":"MinhaSenha123!" }'

# 2) Criar usuários Fake
curl -X POST http://localhost:8080/api/user \
  -H 'Content-Type: application/json' \
  -d '{ "email":"user001@domain.com", "username":"user001", "password":"MinhaSenha123!", "confirm_password":"MinhaSenha123!" }'

curl -X POST https://auth-fast-api.vercel.app/api/user \
  -H 'Content-Type: application/json' \
  -d '{ "email":"user002@domain.com", "username":"user002", "password":"MinhaSenha123!", "confirm_password":"MinhaSenha123!" }'


# 2) Reenviar código (se necessário)
curl -X POST https://auth-fast-api.vercel.app/api/user/auth/verification-code \
  -H 'Content-Type: application/json' \
  -d '{"login":"lfcontato"}'



# 3) Verificar via link (substitua CODE)
curl "https://auth-fast-api.vercel.app/api/user/auth/verify-link?login=lfcontato&code=CODE"

# 4) Login
curl -X POST https://auth-fast-api.vercel.app/api/user/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"lfcontato","password":"MinhaSenha123!"}'

## Fluxo de testes (local)

# 1) Criar usuário
curl -X POST http://localhost:8080/user \
  -H 'Content-Type: application/json' \
  -d '{ "email":"user@example.com", "username":"usuario", "password":"MinhaSenha123!", "confirm_password":"MinhaSenha123!" }'

# 2) Reenviar código
curl -X POST http://localhost:8080/user/auth/verification-code \
  -H 'Content-Type: application/json' \
  -d '{"login":"usuario"}'

# 3) Verificar via link (substitua CODE)
curl "http://localhost:8080/user/auth/verify-link?login=usuario&code=CODE"

# 4) Login
curl -X POST http://localhost:8080/user/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"usuario","password":"MinhaSenha123!"}'
