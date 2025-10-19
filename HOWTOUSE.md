Arquivo: HOWTOUSE.md
Resumo: Guia completo e descritivo de consumo da API (autenticação, endpoints, formatos de requisição e resposta, exemplos e boas práticas). Adequado para uso por agentes/IA e integradores.

# Visão Geral

Esta API implementa autenticação via JWT com fluxo de Access Token (curta duração) e Refresh Token (longa duração). Endpoints atuais permitem:
- Verificação de saúde do serviço.
- Login de administrador (username/password) e emissão de tokens.
- Renovação de tokens (rotação de refresh token).

Outros recursos (CRUD de administradores, verificação de conta, recuperação de senha, bloqueios, ACL por papéis) constam no README e serão adicionados em fases futuras. Este documento descreve em detalhes como autenticar e consumir os endpoints disponíveis hoje, com notas para os endpoints planejados.

# Bases de URL

- Ambiente local (servidor de desenvolvimento):
  - Base: `http://localhost:8080`
- Ambiente Vercel (serverless, com rewrites):
  - Base: `https://<seu-projeto>.vercel.app/api`

As rotas documentadas abaixo assumem a base local. Em Vercel, prefixe com `/api` se necessário (ex.: `/api/admin/auth/token`).

# Autenticação e Tokens

- Login retorna dois tokens:
  - `access_token`: JWT assinado (HS256), válido por tempo curto (default 1800s).
  - `refresh_token`: token opaco aleatório, válido por tempo maior (default 2592000s) e rotacionado a cada refresh.
- Para rotas protegidas, envie o Access Token no cabeçalho HTTP:
  - `Authorization: Bearer <ACCESS_TOKEN>`
- Quando o Access expirar, use o Refresh no endpoint de refresh para obter novo par de tokens. O refresh anterior é revogado (rotação) e um novo é emitido.

## Conteúdo do JWT (Access Token)

O payload do JWT inclui, no mínimo:
- `sub`: Identificador do sujeito, formato `"admin|<id>"`.
- `sid`: ID da sessão (para auditoria/possível revogação futura).
- `sro`: Papel global de sistema (ex.: `root`, `admin`).
- `wss`: Mapa de papéis por workspace (futuro; hoje retorna vazio `{}`).
- `exp`: Época de expiração em segundos.

Assinatura: HS256 usando `SECRET_KEY` do servidor.

# Formato de Erros

Respostas de erro seguem um envelope consistente:
```json
{
  "success": false,
  "code": "AUTH_401_001",
  "message": "Descrição do erro",
  "locale_key": "error.not_implemented" (opcional),
  "path": "/rota" (quando 404)
}
```

Exemplos de códigos já utilizados:
- `AUTH_400_001`: JSON inválido no login
- `AUTH_400_002`: refresh_token ausente
- `AUTH_401_001`: credenciais inválidas/nao autorizadas no login
- `AUTH_401_002`: refresh inválido/nao autorizado
- `HTTP_404`: rota não encontrada

# Endpoints Atuais

## Health Check
- Método: GET
- Rota: `/healthz`
- Autenticação: Não necessária
- 200 OK
  - Corpo:
  ```json
  {"ok": true, "service": "auth_fast_api", "status": "healthy"}
  ```

## Login de Administrador
- Método: POST
- Rota: `/admin/auth/token`
- Autenticação: Não necessária
- Corpo (JSON):
  ```json
  {"username": "<string>", "password": "<string>"}
  ```
- 200 OK
  - Corpo:
  ```json
  {"success": true, "access_token": "<jwt>", "refresh_token": "<opaque>"}
  ```
- 400 Bad Request: JSON inválido
- 401 Unauthorized: credenciais inválidas

Exemplo curl:
```
curl -X POST http://localhost:8080/admin/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"stringst"}'
```

## Renovação de Tokens (Refresh)
- Método: POST
- Rota: `/admin/auth/token/refresh`
- Autenticação: Não necessária (usa token opaco de refresh no corpo)
- Corpo (JSON):
  ```json
  {"refresh_token": "<opaque>"}
  ```
- 200 OK
  - Corpo:
  ```json
  {"success": true, "access_token": "<jwt>", "refresh_token": "<opaque>"}
  ```
- 400 Bad Request: body ausente/malformado
- 401 Unauthorized: refresh inválido/expirado/revogado

Exemplo curl:
```
curl -X POST http://localhost:8080/admin/auth/token/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<REFRESH_TOKEN_DO_LOGIN>"}'
```

## Criar Administrador
- Método: POST
- Rota: `/admin/`
- Autenticação: `Authorization: Bearer <ACCESS_TOKEN>` (papel do solicitante deve ser superior ao `system_role` alvo)
- Corpo (JSON):
  ```json
  {"email":"novo@dominio.com","username":"novo_admin","password":"SenhaForte123","system_role":"user"}
  ```
- 201 Created
  - Corpo:
  ```json
  {"success":true,"admin_id":1,"username":"novo_admin","email":"novo@dominio.com","system_role":"user"}
  ```
- 401/403: token ausente/inválido ou permissão insuficiente
- 409: `email` ou `username` já existentes

Observação: após a criação, um e-mail é enviado ao novo administrador usando o template configurado em `ADMIN_CREATED_TEMPLATE_NAME` (padrão `admin_created.html`).

# Fluxo Recomendado para Clientes/IA
1. Efetue login com `username` e `password` e armazene `access_token` e `refresh_token` de forma segura.
2. Para chamadas a recursos protegidos, envie `Authorization: Bearer <access_token>`.
3. Ao receber 401 por expiração do access, chame o endpoint de refresh com o `refresh_token` atual, substitua ambos os tokens pelo novo par e repita a chamada original.
4. Nunca reutilize um refresh já rotacionado (ele é revogado após o uso com sucesso).

# Exemplos com REST Client (VS Code)

Arquivos prontos em `tests/`:
- `tests/health.http` – GET `/healthz`.
- `tests/auth.http` – fluxo de login e refresh, lendo `ROOT_AUTH_USER` e `ROOT_AUTH_PASSWORD` do `.env` via `{{$dotenv ...}}`.

Passos:
1) Inicie a API: `go run ./cmd/server`
2) Abra `tests/auth.http` e clique em “Send Request” no bloco `@login`, depois no bloco `@refresh`.

# Ambiente e Configuração

- Banco de dados padrão: SQLite (arquivo `database_test.db`).
- Mudar para Postgres: defina `DATABASE_URL` como `postgres://user:pass@host:port/dbname?sslmode=disable`.
- Variáveis relevantes:
  - `SECRET_KEY` (HS256)
  - `TOKEN_ACCESS_EXPIRE_SECONDS` (default 1800)
  - `TOKEN_REFRESH_EXPIRE_SECONDS` (default 2592000)
  - `ROOT_AUTH_USER`, `ROOT_AUTH_EMAIL`, `ROOT_AUTH_PASSWORD` (seed do usuário root na primeira execução)
  - `LOG_LEVEL` (DEBUG, INFO, WARN, ERROR) – controla verbosidade de logs da API (requisições e eventos)

## E-mails (SMTP)

O serviço de e-mail está disponível em `internal/services/email` e suporta `STARTTLS`, `SSL/TLS` e envio sem TLS (apenas para ambientes controlados). Configure via `.env`:

- `EMAIL_SERVER_USERNAME`, `EMAIL_SERVER_PASSWORD`
- `EMAIL_SERVER_SMTP_HOST`, `EMAIL_SERVER_SMTP_PORT`
- `EMAIL_SERVER_SMTP_ENCRYPTION` (valores: `STARTTLS`, `SSL/TLS`, `NONE`)
- `EMAIL_FROM_ADDRESS`, `EMAIL_FROM_NAME`
- `EMAIL_SERVER_TEMPLATE_DIR` (padrão: `template_email`)
- `EMAIL_TEMPLATE_NAME`, `SECURITY_TEMPLATE_NAME`, `ADMIN_CREATED_TEMPLATE_NAME`
- `EMAIL_CC_ADDRESSES`, `EMAIL_BCC_ADDRESSES` (separadas por vírgula)

Exemplo de uso:

```go
import (
  "context"
  "time"
  "github.com/lfcontato/auth_fast_api/internal/config"
  emailsvc "github.com/lfcontato/auth_fast_api/internal/services/email"
)

func sendExample() error {
  cfg := config.Load()
  mailer := emailsvc.FromConfig(cfg)
  ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
  defer cancel()
  return mailer.Send(ctx, emailsvc.Params{
    To: []string{"destinatario@exemplo.com"},
    Subject: "Assunto de Teste",
    TemplateName: cfg.EmailTemplateName,
    Data: map[string]any{
      "Title":   "Olá!",
      "Message": "Este é um e-mail de teste.",
    },
  })
}
```

Crie o template HTML em `template_email/email_notifications.html` (ou outro nome configurado):

```html
<html>
  <body>
    <h1>{{.Title}}</h1>
    <p>{{.Message}}</p>
  </body>
</html>
```

Templates incluídos por padrão em `template_email/`:
- `email_notifications.html` – Notificação genérica com `Title`, `Message`, `ActionURL`, `ActionText`, `FooterText`, `ExtraNote`.
- `security_notifications.html` – Alertas de segurança com `Event`, `Time`, `IPAddress`, `UserAgent`, além de `Title/Message`.
- `admin_created.html` – Boas-vindas ao novo admin com `Email`, `Username`, `SystemRole`, `CreatedByRole`, `LoginURL` (opcional).

Para enviar o e-mail de criação de administrador, configure `ADMIN_CREATED_TEMPLATE_NAME=admin_created.html` (padrão já aplicado) e certifique-se de que o arquivo exista em `EMAIL_SERVER_TEMPLATE_DIR`.

Notas por provedor:
- Gmail: `smtp.gmail.com`, 587 `STARTTLS` (ou 465 `SSL/TLS`). Use App Password quando 2FA estiver ativo.
- Outlook/Hotmail (Microsoft 365): `smtp.office365.com`, 587 `STARTTLS`.

# Endpoints Planejados (Não implementados ainda)

Os itens abaixo constam no README e serão expandidos. Interfaces e semântica previstas:

- Verificação e recuperação de conta (rotas `/admin/auth/verify`, `/admin/auth/verify-link`, `/admin/auth/password-recovery`, `/admin/auth/verification-code`).
  - Objetivo: confirmar e-mail, reenviar código, iniciar e concluir recuperação de senha.
- Gerenciamento hierárquico de administradores (`/admin/` CRUD e detalhes, alteração de senha/e-mail próprios).
  - Regras por `system_role` (guest < user < admin < root) e prevenção de operações em papéis superiores.
- Bloqueios e segurança (`/admin/unlock`, `/admin/unlock/all`).
  - Consultar e remover bloqueios (rate limit, tentativas malsucedidas), com autorização adequada.

Quando estes endpoints forem disponibilizados, utilizarão `Authorization: Bearer <ACCESS_TOKEN>` e respostas com envelope padronizado (`success`, `code`, `message`).

# Boas Práticas

- Proteja os tokens: armazene `refresh_token` em local seguro (ex.: armazenamento seguro do servidor/cliente), evite expô-lo em logs.
- Renove tokens próximo do vencimento do `access_token` para minimizar falhas por expiração.
- Trate códigos 4xx/5xx com retentativas prudentes e backoff quando apropriado.
- Não compartilhe `SECRET_KEY` do servidor. A validação do JWT pelo cliente é opcional; caso deseje validar, use HS256 e a chave compartilhada conforme seu contexto de confiança.

# Compatibilidade

- Local: `go run ./cmd/server` expõe `http://localhost:8080`.
- Vercel: `vercel dev` expõe `/api/...` com o mesmo handler (recomenda-se preferir chamadas via `/api`).
