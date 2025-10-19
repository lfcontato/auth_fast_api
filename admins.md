Arquivo: admins.md
Resumo: Guia prático das rotas de administradores com exemplos cURL para teste rápido.

# Guia de Administradores (Rotas + cURL)

Use estes exemplos para validar os fluxos de administrador em ambiente local.

Pré‑requisitos

- Banco de dados via `DATABASE_URL` (ou SQLite padrão `database_test.db`).
- `SECRET_KEY` definida.
- Serviço local: `go run ./cmd/server` (escuta em http://localhost:8080).
- Opcional (e‑mail): configurar SMTP no `.env` para envio real de e‑mails.

Base local

- Todas as chamadas abaixo usam `http://localhost:8080`.

Seed do administrador root

- Defina no `.env`: `ROOT_AUTH_USER`, `ROOT_AUTH_EMAIL`, `ROOT_AUTH_PASSWORD`.
- Ao iniciar o servidor, o root é criado automaticamente, se não existir.

Rotas e cURL

- Healthcheck
  - GET `/healthz`
  - cURL:
    - `curl -i http://localhost:8080/healthz`
  - Resposta (200):
    ```json
    { "ok": true, "service": "auth_fast_api", "status": "healthy" }
    ```

- Raiz (opcional)
  - GET `/`
  - cURL:
    - `curl -i http://localhost:8080/`
  - Resposta (200):
    ```json
    { "ok": true, "service": "auth_fast_api", "version": "0.1.0", "endpoints": ["/healthz", "/admin/auth/token", "/admin/auth/token/refresh", "/admin/auth/password-recovery", "/admin (GET)"] }
    ```

- Login (obter tokens)
  - POST `/admin/auth/token`
  - Body: `{ "username": "<ROOT_AUTH_USER>", "password": "<ROOT_AUTH_PASSWORD>" }`
  - Regra de verificação: somente contas com `is_verified = 1` podem fazer login e acessar rotas autenticadas. Contas não verificadas recebem `401`.
  - cURL:
    - `curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"seu_user","password":"sua_senha"}'`
  - Dica: para guardar tokens via `jq` (opcional)
    - `TOKENS=$(curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"seu_user","password":"sua_senha"}')`
    - `ACCESS=$(echo "$TOKENS" | jq -r .access_token)`
    - `REFRESH=$(echo "$TOKENS" | jq -r .refresh_token)`
  - Resposta (200):
    ```json
    { "success": true, "access_token": "<JWT>", "refresh_token": "<REFRESH>" }
    ```
  - Possíveis erros:
    - 400 `AUTH_400_001` JSON inválido
    - 401 `AUTH_401_001` Credenciais inválidas

- Refresh de token
  - POST `/admin/auth/token/refresh`
  - Body: `{ "refresh_token": "<REFRESH_TOKEN>" }`
  - cURL:
    - `curl -sS -X POST http://localhost:8080/admin/auth/token/refresh -H 'Content-Type: application/json' -d '{"refresh_token":"<REFRESH_TOKEN>"}'`
  - Resposta (200):
    ```json
    { "success": true, "access_token": "<JWT>", "refresh_token": "<REFRESH>" }
    ```
  - Possíveis erros:
    - 400 `AUTH_400_002` JSON inválido ou refresh ausente
    - 401 `AUTH_401_002` Refresh token inválido

- Criar novo administrador
  - POST `/admin`
  - Auth: `Authorization: Bearer <ACCESS_TOKEN>`
  - Body:
    - `{ "email": "luis.fernando.pereira.procempa@gmail.com", "username": "luis.fernando.pereira.procempa", "password": "stringst", "system_role": "user" }`
  - cURL:
    - `curl -sS -X POST http://localhost:8080/admin -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' -d '{"email":"novo@dominio.com","username":"novo_admin","password":"SenhaForte123","system_role":"user"}'`
  - Observações:
    - Hierarquia: `guest < user < admin < root` (é preciso ter nível superior ao do alvo).
    - Se `password` for omitida, o sistema gera uma senha de 8 dígitos.
    - Um e‑mail automático é enviado com senha/código/link de verificação.
  - Resposta (201):
    ```json
    { "success": true, "admin_id": 2, "username": "novo_admin", "email": "novo@dominio.com", "system_role": "user" }
    ```
  - Possíveis erros:
    - 401 `AUTH_401_003` Token ausente/inválido
    - 400 `AUTH_400_003` JSON inválido
    - 400 `AUTH_400_004` Campos obrigatórios ausentes
    - 400 `AUTH_400_005` Senha menor que 8 caracteres
    - 403 `AUTH_403_001` Papel insuficiente
    - 409 `AUTH_409_001` Email/username já existente
    - 500 `AUTH_500_001` Falha ao processar senha

- Listar administradores (autenticada)
  - GET `/admin`
  - Regra: você vê apenas papéis com prioridade inferior ao seu; `root` vê todos (incluindo `root`).
  - Headers: `Authorization: Bearer <ACCESS_TOKEN>`
  - Paginação: `offset` (default 0) e `limit` (default 20, máx. 100)
  - cURL (primeira página):
    - `curl -sS -X GET 'http://localhost:8080/admin?offset=0&limit=20' -H "Authorization: Bearer $ACCESS"`
  - cURL (página seguinte):
    - `curl -sS -X GET 'http://localhost:8080/admin?offset=20&limit=20' -H "Authorization: Bearer $ACCESS"`
  - Resposta (200):
    ```json
    {
      "success": true,
      "offset": 0,
      "limit": 20,
      "items": [
        { "id": 1, "email": "root@dominio.com", "username": "root", "system_role": "root", "is_verified": true }
      ]
    }
    ```
  - Possíveis erros:
    - 401 `AUTH_401_005` Token ausente/inválido
    - 500 `AUTH_500_014` Falha ao consultar administradores
    - 500 `AUTH_500_015` Falha ao consultar administradores
    - 500 `AUTH_500_016` Falha ao ler resultado
    - 500 `AUTH_500_017` Falha ao ler resultado

- Verificação de conta pelo código na URL
  - POST `/admin/auth/verify-code/{hash}` (pública)
  - Body: `{ "password": "<senha_inicial_ou_nova>" }`
  - cURL:
    - `curl -sS -X POST http://localhost:8080/admin/auth/verify-code/<CODE> -H 'Content-Type: application/json' -d '{"password":"<SENHA>"}'`
  - Resposta (200):
    ```json
    { "success": true, "verified": true }
    ```
  - Possíveis erros:
    - 400 `AUTH_400_006` JSON inválido
    - 400 `AUTH_400_007` Código ou senha ausentes/invalidos
    - 400 `AUTH_400_008` Código inválido ou expirado
    - 401 `AUTH_401_004` Senha inválida
    - 500 `AUTH_500_003` Falha ao iniciar transação
    - 500 `AUTH_500_004` Falha ao atualizar verificação
    - 500 `AUTH_500_005` Falha ao consumir código
    - 500 `AUTH_500_006` Falha ao confirmar verificação

- Verificação de conta (compatibilidade; código no corpo)
  - POST `/admin/auth/verify` (pública)
  - Body: `{ "code": "<hash>", "password": "<senha_inicial_ou_nova>" }`
  - cURL:
    - `curl -sS -X POST http://localhost:8080/admin/auth/verify -H 'Content-Type: application/json' -d '{"code":"<CODE>","password":"<SENHA>"}'`
  - Resposta (200):
    ```json
    { "success": true, "verified": true }
    ```
  - Possíveis erros: iguais ao endpoint com código na URL

- Recuperação de senha (não autenticada)
  - POST `/admin/auth/password-recovery`
  - Body: `{ "email": "admin@dominio.com" }`
  - cURL:
    - `curl -sS -X POST http://localhost:8080/admin/auth/password-recovery -H 'Content-Type: application/json' -d '{"email":"admin@dominio.com"}'`
  - Comportamento:
    - Gera nova senha (8 dígitos), marca `is_verified = 0`, cria novo código e envia e‑mail com senha/código e link de verificação.
    - Resposta é 200 OK mesmo se o e‑mail não existir (evita enumeração).
  - Resposta (200):
    ```json
    { "success": true, "sent": true }
    ```
  - Possíveis erros:
    - 400 `AUTH_400_009` JSON inválido
    - 400 `AUTH_400_010` E‑mail é obrigatório
    - 500 `AUTH_500_007` Falha ao consultar usuário
    - 500 `AUTH_500_008` Falha ao processar senha
    - 500 `AUTH_500_009` Falha ao gerar código de verificação
    - 500 `AUTH_500_010` Falha ao iniciar transação
    - 500 `AUTH_500_011` Falha ao atualizar senha
    - 500 `AUTH_500_012` Falha ao criar código de verificação
    - 500 `AUTH_500_013` Falha ao confirmar recuperação

Notas importantes

- Base de URL nos e‑mails: se `PUBLIC_BASE_URL` estiver definido, ele é usado; caso contrário, a API deduz a base a partir dos cabeçalhos da requisição (`X-Forwarded-Proto`/`X-Forwarded-Host` ou `Host`). Isso torna o deploy portátil em qualquer hospedagem/reverso.
- O tamanho do código de verificação é definido em `internal/contants/contants.go` (`VerificationCodeLength`, padrão 64).
- Após verificação bem‑sucedida, `admins.is_verified` = 1 e o código é consumido.
