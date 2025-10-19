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
- Ambiente Vercel (serverless):
  - Base recomendada: `https://<seu-projeto>.vercel.app`
  - Observação: as rotas também funcionam com `/api` por compatibilidade (ex.: `/api/healthz`). Rewrites já permitem `/healthz` e `/admin` sem prefixo.

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

Exemplo curl (sem MFA):
```
curl -X POST http://localhost:8080/admin/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"stringst"}'
```

MFA por E‑mail (opcional)

- Quando `MFA_EMAIL_ENABLED=true`, o login exige um segundo fator por código enviado por e‑mail.
- Fluxo:
  1) POST `/admin/auth/token` com `username/password` → `202 Accepted` com `{ "mfa_required": true, "mfa_tx": "..." }`.
  2) O usuário recebe o código (por padrão, 6 dígitos) no e‑mail.
  3) POST `/admin/auth/mfa/verify` com `{ "mfa_tx": "...", "code": "123456" }` → `200 OK` com tokens.
- Limites: tentativas por `mfa_tx` (default 5) e expiração do código (default 10 min; configurável por env).

Exemplo curl (verificar MFA):
```
curl -X POST http://localhost:8080/admin/auth/mfa/verify \
  -H 'Content-Type: application/json' \
  -d '{"mfa_tx":"<do passo 1>","code":"123456"}'
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
  {
    "email":"novo@dominio.com",
    "username":"novo_admin",
    "password":"SenhaForte123",
    "system_role":"user",
    "subscription_plan":"monthly"
  }
  ```
- 201 Created
  - Corpo:
  ```json
  {
    "success":true,
    "admin_id":1,
    "username":"novo_admin",
    "email":"novo@dominio.com",
    "system_role":"user",
    "subscription_plan":"monthly",
    "expires_at":"2025-11-19T00:00:00Z"
  }
  ```
- 401/403: token ausente/inválido ou permissão insuficiente
- 409: `email` ou `username` já existentes

Observação: após a criação, um e-mail é enviado ao novo administrador usando o template configurado em `ADMIN_CREATED_TEMPLATE_NAME` (padrão `admin_created.html`).

## Alterar Papel (system_role)
- Método: PATCH
- Rota: `/admin/{admin_id}/system-role`
- Autenticação: `Authorization: Bearer <ACCESS_TOKEN>`
- Corpo (JSON):
  ```json
  {"system_role":"user|admin|root|guest"}
  ```
- Regras de hierarquia:
  - O solicitante deve ter papel estritamente superior ao papel atual do alvo e ao novo papel desejado.
  - `root` pode alterar o papel de qualquer administrador (inclusive promover/demover para `root`).
- Respostas:
  - 200 OK: `{ "success": true, "admin_id": <id>, "old_role": "user", "new_role": "admin" }`
  - 401/403 conforme autorização insuficiente
  - 404 se admin alvo não encontrado

## Alterar Plano (subscription_plan)
- Método: PATCH
- Rota: `/admin/{admin_id}/subscription-plan`
- Autenticação: `Authorization: Bearer <ACCESS_TOKEN>`
- Corpo (JSON):
  ```json
  {"subscription_plan":"minute|hourly|daily|trial|monthly|semiannual|annual|lifetime"}
  ```
- Regras:
  - `root` pode definir qualquer plano.
  - Demais administradores podem definir até `semiannual` (inclusive).
  - `expires_at` é recalculado automaticamente:
    - `lifetime`: `expires_at = null`
    - `annual`: +1 ano; `semiannual`: +6 meses; `monthly`: +1 mês; `trial`: +7 dias; `daily`: +1 dia; `hourly`: +1 hora; `minute`: +5 minutos
- Tokens respeitam o plano:
  - Access/Refresh nunca ultrapassam `expires_at` (exceto `lifetime`).
- Respostas:
  - 200 OK: `{ "success": true, "admin_id": <id>, "new_plan": "monthly" }`
  - 401/403 conforme autorização
  - 404 se admin não encontrado

Exemplos de cálculo de expires_at

Considerando agora = `2025-10-19T12:00:00Z` (apenas ilustrativo):
- `minute`     → `2025-10-19T12:05:00Z`
- `hourly`     → `2025-10-19T13:00:00Z`
- `daily`      → `2025-10-20T12:00:00Z`
- `trial`      → `2025-10-26T12:00:00Z`
- `monthly`    → `2025-11-19T12:00:00Z`
- `semiannual` → `2026-04-19T12:00:00Z`
- `annual`     → `2026-10-19T12:00:00Z`
- `lifetime`   → `null`

Exemplo de resposta após PATCH (monthly)
```json
{ "success": true, "admin_id": 2, "new_plan": "monthly" }
```

Observação: os tokens (access/refresh) nunca ultrapassam `expires_at` (exceto `lifetime`).

## Verificação de Conta
- Método: POST
- Rotas:
  - `/admin/auth/verify-code/{code}` (recomendado; pública). Corpo: `{ "password": "<senha_inicial>" }`
  - `/admin/auth/verify` (compatibilidade; pública). Corpo: `{ "code": "<64 hex>", "password": "<senha_inicial>" }`
- 200 OK: `{ "success": true, "verified": true }`
- Erros: `AUTH_400_006/007/008`, `AUTH_401_004`, `AUTH_500_003..006`
- Observação: códigos expiram (24h) — após expirar, a verificação é negada.

Exemplo curl (code na URL):
```
curl -X POST http://localhost:8080/admin/auth/verify-code/<CODE> \
  -H 'Content-Type: application/json' \
  -d '{"password":"<SENHA>"}'
```

## Recuperação de Senha
- Método: POST
- Rota: `/admin/auth/password-recovery` (pública)
- Corpo: `{ "email": "<admin@dominio.com>" }`
- Comportamento: gera nova senha (8 dígitos), `is_verified=0`, cria novo código e envia e-mail com senha/código/link de verificação.
- 200 OK: `{ "success": true, "sent": true }` (também quando e-mail não existe, para evitar enumeração)
- Em Vercel, envio é síncrono (a função aguarda o SMTP concluir).
- Rate limit: por IP (10/h) e por e‑mail (3/15min). Excedendo, retorna 429.

## Alterar Senha Própria
- Método: PATCH
- Rota: `/admin/password`
- Autenticação: `Authorization: Bearer <ACCESS_TOKEN>`
- Corpo (JSON):
  ```json
  {"current_password":"<senha_atual>","new_password":"<nova_senha>"}
  ```
- Política de senha:
  - Padrão: mínimo 8 caracteres.
  - Estrito (quando `PASSWORD_POLICY_STRICT=true`): exige maiúscula, minúscula, número e caractere especial.
- 200 OK: `{ "success": true }`
- Erros: `AUTH_400_030/031`, `AUTH_400_005`, `AUTH_401_005/006`, `AUTH_404_001`, `AUTH_500_030/031`

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
  - `PUBLIC_BASE_URL` – base usada para montar links de verificação enviados por e‑mail
  - `PASSWORD_POLICY_STRICT` – quando `true`, aplica política de senha forte (maiúscula/minúscula/número/especial) em criação/recuperação/troca de senha
  - `REDIS_URL` – conexão Redis para rate limit/lockout
  - MFA por e‑mail:
    - `MFA_EMAIL_ENABLED` (true/false)
    - `MFA_CODE_TTL_MINUTES` (default 10)
    - `MFA_CODE_LENGTH` (default 6)
    - `MFA_MAX_ATTEMPTS` (default 5)
  - Em Vercel: se `DATABASE_URL` estiver vazio, a API usa SQLite em `/tmp/auth_fast_api.db` (dados efêmeros). Para produção, configure Postgres via `DATABASE_URL`.

# Recursos Pendentes/Planejados

- Detalhar/Remover administrador: GET/DELETE `/admin/{admin_id}` (hierarquia com salvaguardas).
- Alterar e‑mail próprio: PATCH `/admin/email` (reinicia verificação + reenvio de código).
- Governança de lockouts: GET/POST `/admin/unlock`, GET `/admin/unlock/all`.
- Verificação pública e reenvio: GET `/admin/auth/verify-link`, POST `/admin/auth/verification-code`.
- Sessões: POST `/admin/auth/logout` e `/admin/auth/logout/all` (revoga sessão atual/todas).
- DTO/i18n: padronizar envelope e localizar mensagens (pt-BR/en-US).

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
- `admin_created.html` – Boas-vindas ao novo admin com `Email`, `Username`, `SystemRole`, `CreatedByRole`, `Senha inicial`, `Código` e `VerifyURL`.
Observação: os templates também estão embutidos no binário (via embed). Se o arquivo não existir no filesystem, o serviço usa o template embutido.

Para enviar o e-mail de criação de administrador, configure `ADMIN_CREATED_TEMPLATE_NAME=admin_created.html` (padrão já aplicado) e certifique-se de que o arquivo exista em `EMAIL_SERVER_TEMPLATE_DIR`.

Notas por provedor:
- Gmail: `smtp.gmail.com`, 587 `STARTTLS` (ou 465 `SSL/TLS`). Use App Password quando 2FA estiver ativo.
- Outlook/Hotmail (Microsoft 365): `smtp.office365.com`, 587 `STARTTLS`.

# Endpoints Planejados (Não implementados ainda)

Os itens abaixo constam no README e serão expandidos. Interfaces e semântica previstas:

- Reenvio de código de verificação (`/admin/auth/verification-code`) e link público (`/admin/auth/verify-link`).
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
