# 🚀 API de Autenticação e Autorização (Auth_Fast_API) - Versão Completa

Este é o **prompt de sistema final** para a construção da API de autenticação e autorização (`Auth_Fast_API`). O objetivo é estruturar o modelo de dados, as regras de negócio e a lógica de autorização, sem gerar código.

Voce deve manter um arquivo de contexto, chamado docs/CONTEXTO.md que vai adicionar sempre o prompt anterior, mantendo com todas as alterações feitas no programa e as novas funcionalidades.

no inicio de cada arquivo deve conter o caminho e o resumo de que faz o arquivo
antes de cada função deve descrever o que ela faz.

O sistema deve:
* Persistir dados em **PostgreSQL ou SQLite**.
* Receber variáveis de configuração via **arquivo `.env`**.
* Implementar padrão **DTO** para mensagens de sistema com localização (`pt_br.json` e `en.json`).
* Seguir uma arquitetura limpa/modular (conforme sugerido na estrutura de pastas em `internal/`).

---

## Estrutura de Pastas por Domínio (Atual)

Arquivos principais da API segmentados por domínio. Cada domínio possui um roteador e arquivos de handlers específicos.

```
pkg/httpapi/
  httpapi.go                   # Entrada HTTP; init (DB/Redis/Email), utilitários, root/health/openapi. Delegação por domínio.
  router_admin.go              # Roteamento de Admin (/admin/...)
  admin_handlers.go            # Handlers de Admin (auth, verify, recovery, CRUD, PAT)
  router_users.go              # Roteamento de Users (/user/auth/...)
  users_handlers.go            # Handlers de Users (login/refresh/verify/recovery)
  router_spaces.go             # Roteamento de UsersSpaces (/user/spaces/...)
  spaces_handlers.go           # Handlers de UsersSpaces (criar/listar; membership add/list/update/remove)
  router_tools_faciendum.go    # Rotas da Tool Faciendum (boards/tracks/tasks) com ACL e persistência
  router_tools_automata.go     # Rotas da Tool Automata (keys/prompts/chats) com ACL e persistência

internal/tools/
  faciendum/migrate.go         # Migrações do banco do Faciendum (boards, tracks, tasks)
  automata/migrate.go          # Migrações do banco do Automata (api_keys, prompts, chats)

internal/db/
  migrate.go                   # Migrações core (admins, users, sessions, verifications, PAT)
  db.go, dsn.go                # Conexão/parse DSN (Postgres/SQLite) e helpers

internal/services/
  auth/service.go              # Serviço de autenticação de Admin (login/refresh, rotação)
  email/service.go             # Serviço de e‑mail (SMTP) e template loader

internal/kv/
  redis.go                     # Inicialização e helpers (rate limit, locks, get/set)

internal/config/
  config.go                    # Carregamento de variáveis de ambiente (env)

internal/contants/
  contants.go                  # Constantes globais (tamanho de códigos, assuntos de e‑mail, etc.)

cmd/server/
  main.go                      # Servidor local (escuta HTTP), usa pkg/httpapi/Handler

api/
  index.go                     # Entrada serverless (Vercel), aponta para pkg/httpapi/Handler
```

Notas:
- `httpapi.go` mantém apenas utilitários comuns, inicialização (DB/Redis/Email), rotas básicas e delegação por domínio; handlers residem em arquivos por domínio.
- Tools possuem bancos separados e migrações próprias; a inicialização ocorre no `init()` de httpapi.go com leitura de `FACIENDUM_DATABASE_URL` e `AUTOMATA_DATABASE_URL`.
- ACL por UsersSpace é aplicada nas rotas de Tools e em operações de espaço/membership.

Padrões e enumerações (Admins/Users)

- Admins
  - `system_role`: default `guest`; opções `guest|user|admin|root`.
  - `subscription_plan`: default `trial`; opções `trial|monthly|semiannual|annual|lifetime`.
- Users
  - `tools_role`: default `guest`; opções `guest|user|admin|root`.
  - `subscription_plan`: default `trial`; opções `trial|monthly|semiannual|annual|lifetime`.

Regra de documentação

- Em todos os endpoints e exemplos, listar explicitamente os campos opcionais e seus valores padrão (defaults) para facilitar integrações (ex.: MCP).
- Senhas em cadastro de Admin e (quando existir) de Usuário são opcionais e geradas automaticamente quando omitidas (política forte com `PASSWORD_POLICY_STRICT=true`).

---

### 1. Modelo de Dados e Estrutura (Completo)

As entidades a seguir definem a persistência do sistema.

#### 1.1. Administradores (`admins`) e Sessões/Contatos

| Tabela | Campos Chave e Lógica | Sugestões/Detalhes |
| :--- | :--- | :--- |
| **`admins`** | `id`, `email` (Único), `password_hash`, `username` (Único), `owner_id` (Admin criador), `system_role` (Global), `resource_role` (Genérico), `subscription_plan`, `account_status`, `is_verified`. | Garantir que `owner_id` seja opcional/nulo para o primeiro usuário `root`. |
| **`admins_sessions_local`** | `admin_id` (FK), `session_id` (UUID), `family_id` (Rotação de Refresh), `refresh_token_hash`, `expires_at`, `revoked_at`, `revoked_reason`. | Modelo obrigatório para gerenciar o ciclo de vida e rotação do Refresh Token. |
| **`admin_contacts`** | `admin_id` (FK), `contact_type` (`email`, `sms`, `whatsapp`, etc.), `contact_value`, `is_main`. | Modelo para múltiplos contatos. |

#### 1.2. Usuários (`users`)

| Tabela | Campos Chave e Lógica | Sugestões/Detalhes |
| :--- | :--- | :--- |
| **`users`** | `id`, `email` (Único), `password_hash`, `username` (Único), `system_role` (Principalmente 'user' ou 'guest'), `account_status`, `is_verified`. | Similar a `admins`, mas sem vínculo direto com `owner_id` ou plano de assinatura. |

#### 1.3. Workspaces (`workspaces`) e Membros

| Tabela | Campos Chave e Lógica | Sugestões/Detalhes |
| :--- | :--- | :--- |
| **`workspaces`** | `id`, `owner_user_id` (FK para `users.id`), `name` (Único), `hash_id` (UUID/Hash para URL), `subscription_plan`. | O `hash_id` é usado na rota `/app/workspace/{hash_id}/...`. |
| **`workspace_members`** | `workspace_id` (FK), `user_id` (FK), `resource_role` (Papel local - crucial para a ACL), `status` (`invited`, `active`). | Chave única em (`workspace_id`, `user_id`). Sugestão: Adicionar `invited_by_id`. |

---

### 2. Papéis e Política de Autorização

O controle de acesso é dividido em escopo Global (SystemRole) e Local (ResourceRole).

#### 2.1. Papéis de Sistema (SystemRole) - Escopo Global (`/admin`)

* **Hierarquia de Privilégios (Crescente):** `guest` < `user` < `admin` < `root`.
* **Regra de Imutabilidade (ROOT):** Administradores de nível inferior (`admin`) **NÃO** podem realizar operações (ver, editar, excluir, criar) sobre usuários/admins de nível igual ou superior (`root`).
* **Lógica:** Usar a função `can_manage_system_role(acting_role, target_role)` que verifica a prioridade estritamente maior.

#### 2.2. Papéis de Recurso (ResourceRole) - Escopo Local (Workspace)

* **Hierarquia de Privilégios (Crescente):** `viewer` < `editor` < `admin` < `owner`.
* **Controle de Membros:**
    * **`owner`:** Gerencia todos os membros (incluindo `admin` do Workspace).
    * **`admin` (Workspace):** Gerencia membros inferiores (`editor`, `viewer`, `user`), mas **não pode gerenciar o `owner`**.
* **Permissão de Recurso:** O papel define as ações CRUD no recurso (ex: `/voters`).
    * **`owner`:** Completa (C,R,U,D, Ocultar, Proteger).
    * **`editor`:** C, R, U.
    * **`viewer`:** R (Apenas leitura).

---

### 3. Autorização e Tokens JWT

O Token de Acesso deve conter todas as informações para autorizar uma rota sem consultar o banco de dados.

#### 3.1. Conteúdo do Token (Payload JWT)

| Campo | Exemplo | Função |
| :--- | :--- | :--- |
| `sub` | `"user|123"` | Tipo e ID do usuário (Subject). |
| `sid` | `"uuid_session_id"` | ID da Sessão (para revogação). |
| `sro` | `"admin"` | SystemRole (Para rotas `/admin`). |
| `wss` | `{"hash1": "owner", "hash2": "editor"}` | Mapa de Workspaces e ResourceRoles (Para rotas `/app`). |
| `exp` | `1678886400` | Tempo de Expiração (Curta Duração para Access Token). |

#### 3.2. Lógica de Validação e Rota

1.  **Validação:** O Token deve ser validado (assinatura, expiração).
2.  **Autorização Global (`/admin/...`):** Checar o valor de `sro`.
3.  **Autorização Local (`/app/workspace/{hash_id}/{recurso}`):**
    * Capturar `{hash_id}` da URL.
    * Consultar o `ResourceRole` no mapa `wss` usando o `{hash_id}`.
    * Realizar a checagem da Permissão de Recurso (ACL) com base no `ResourceRole` e na ação HTTP.

#### 3.3. Segurança e Ciclo de Vida do Token

* **Tokens:** Implementar pares de **Access Token** (curta duração) e **Refresh Token** (longa duração, armazenado de forma segura - ex: HTTP-Only Cookie).
* **Revogação:** Implementar revogação de sessões (usando `sid`) e rotação do Refresh Token (usando `family_id`).

---

### 4. Políticas, Mensagens e Estrutura

#### 4.1. Política de Senhas e Verificação

* **Hash:** Uso obrigatório de algoritmos fortes e lentos (ex: Argon2 ou bcrypt).
* **Complexidade:** Senha mínima de 8 caracteres, exigindo variedade (símbolos, números, maiúsculas/minúsculas).
* **Verificação:** Implementar fluxo de verificação de conta (e-mail) usando os campos de hash e expiração nos modelos.

#### 4.2. Padrão DTO e Localização

* **DTO (Data Transfer Object):** Obrigatório para validação de entrada e tipagem de saída.
* **Mensagens de Erro Padronizadas:** Todas as respostas de erro devem ser estruturadas com: `success: false`, `code` (código único de erro, ex: `AUTH_403_001`), `message` (descrição), e `locale_key` (chave para localização).
* **Localização:** Suporte para **Português (`pt_br.json`)** e **Inglês (`en.json`)**.

#### 4.3. Estrutura de Projeto (Modelo Go/Modular)

A estrutura deve refletir uma arquitetura limpa/modular para facilitar a manutenção e escalabilidade:

```text
/auth_fast_api
├── api/
│   └── index.go            # Ponto de entrada (Handler Vercel/Router)
├── internal/
│   ├── config/             # Configuração e variáveis de ambiente
│   ├── db/                 # Conexão DB, Modelos ORM, Migrações
│   ├── auth/               # Lógica de Hash, JWT (Sign/Verify), Sessões
│   ├── handlers/           # Camada de Apresentação/Rotas (Chama os Services)
│   ├── services/           # Camada de Lógica de Negócio (Regras de Transição)
│   └── domain/             # Enums, DTOs e Value Objects (Modelos de domínio)
├── go.mod
└── vercel.json

# 🔒 Recursos da API de Administração (Auth_Fast_API - Rota /admin)

Esta é a descrição dos endpoints da API de Autenticação e Gerenciamento de Administradores, baseada na especificação OpenAPI fornecida. O foco é em segurança de conta, ciclo de vida do token JWT e gestão hierárquica de usuários `admin`.

---

## 1. Autenticação e Gerenciamento de Sessão (`/admin/auth/`)

| Endpoint | Método | Resumo da Funcionalidade | Detalhes de Segurança |
| :--- | :--- | :--- | :--- |
| **`/admin/auth/token`** | `POST` | **Login e Emissão de Tokens.** Realiza autenticação via `username`/`password` e retorna um par de tokens **JWT** (Access e Refresh). O token inclui `admin_id`, `email` e `admin=true` nas *claims*. | Implementa fluxo OAuth2 Password Bearer. |
| **`/admin/auth/token/refresh`** | `POST` | **Renovação de Tokens.** Recebe um Refresh Token válido e emite um novo par Access/Refresh. | Essencial para rotação de tokens e segurança da sessão. |

---

## 2. Fluxos Transacionais de Conta (Verificação e Recuperação)

Estes endpoints gerenciam a criação segura e a recuperação de contas, com proteções de *rate limiting*.

| Endpoint | Método | Resumo da Funcionalidade | Detalhes de Proteção |
| :--- | :--- | :--- | :--- |
| **`/admin/auth/verify`** | `POST` | **Confirmação de Conta (Token Protegido).** Valida o código de verificação informado pelo administrador **autenticado**. | **Exige Bearer token válido**. Respeita *rate limit* de tentativas e bloqueios temporários. |
| **`/admin/auth/verify-link`** | `GET` | **Confirmação de Conta (Link Público).** Consumido por um link enviado por e-mail, usando parâmetros `login` e `code`. | **Rate limit** por login e códigos com tempo de expiração (`VERIFICATION_CODE_EXPIRE_SECONDS`). |
| **`/admin/auth/password-recovery`** | `POST` | **Redefinição de Senha (Fluxo Público).** Gera um token temporário (via e-mail) ou, com o token válido, redefine a senha. | Tokens temporários expiram. **Rate limit** por e-mail (`PASSWORD_RECOVERY_INTERVAL_SECONDS`). |
| **`/admin/auth/verification-code`** | `POST` | **Reenviar Código de Verificação.** Regenera e envia o código para um administrador ainda não verificado (via `email`). | **Rate limit** de reenvio (`VERIFICATION_RESEND_INTERVAL_SECONDS`) e *throttle* para o código atual. |

---

## 3. Gerenciamento Hierárquico de Administradores (`/admin/`)

Estes recursos implementam o CRUD de administradores, respeitando a hierarquia de `system_role`.

| Endpoint | Método | Resumo da Funcionalidade | Regras de Autorização |
| :--- | :--- | :--- | :--- |
| **`/admin/`** | `POST` | **Criar Administrador.** Cria novo admin com credenciais e gera código de verificação. | **Requer autenticação Bearer.** O solicitante deve ter `system_role` suficiente para criar o papel alvo. |
| **`/admin/`** | `GET` | **Listar Administradores.** Retorna administradores paginados (`offset`/`limit`). | **Requer autenticação Bearer.** Retorna **apenas** registros que o solicitante pode gerenciar (regra de hierarquia de `system_role`). |
| **`/admin/{admin_id}`** | `GET` | **Detalhar Administrador.** Busca um admin específico. | **Requer autenticação Bearer.** Acesso restrito: `system_role` superior para visualizar outros. |
| **`/admin/{admin_id}`** | `DELETE` | **Remover Administrador.** Exclui o administrador e seus contatos. | **Requer autenticação Bearer.** Impede **autoexclusão** e remoção de papéis superiores (`root`). |
| **`/admin/password`** | `PATCH` | **Alterar Senha Própria.** Permite ao admin autenticado trocar sua senha (requer senha atual). | **Rate limit/lock** por falhas consecutivas (monitorado em Redis). E-mail de confirmação após alteração. |
| **`/admin/email`** | `PATCH` | **Alterar E-mail Próprio.** Atualiza o e-mail do admin, o que **reinicia o processo de verificação** (`is_verified = false`). | Novo código é gerado e enviado automaticamente. |
| **`/admin/{admin_id}/system-role`** | `PATCH` | **Alterar Papel (system_role).** Atualiza o `system_role` de um administrador alvo. | Requer autenticação Bearer. A regra é de hierarquia estrita: o solicitante só pode alterar papéis de administradores com papel inferior ao seu e somente para um papel que também seja inferior ao seu. `root` pode alterar qualquer papel, inclusive promover/demover para `root`. |

---

## 4. Gestão de Bloqueios e Segurança

| Endpoint | Método | Resumo da Funcionalidade | Requisitos de Acesso |
| :--- | :--- | :--- | :--- |
| **`/admin/unlock`** | `POST` | **Desbloquear Administrador.** Remove bloqueios temporários (por tentativas malsucedidas) de uma conta alvo (via `email`). | Exige `system_role` (`root` ou `admin`) superior para intervir em outra conta. |
| **`/admin/unlock`** | `GET` | **Consultar Bloqueios do Administrador.** Retorna o estado de bloqueio (`is_blocked_login`, `is_blocked_password`) e tempo de *retry* associado a um `email`. | Exige `system_role` (`root` ou `admin`) suficiente para consulta. |
| **`/admin/unlock/all`** | `GET` | **Listar Bloqueios Ativos.** Retorna todos os bloqueios temporários de login/senha registrados. | Requer autenticação (geralmente restrito a `root` ou `admin`). |
| **`/admin/password-recovery`** | `POST` | **Disparar Recuperação (Admin Controlada).** Gera e envia o token de recuperação para o admin informado (Uso interno/suporte). | Requer **autenticação**. Respeita *rate limit*. |

Backlog (próximas entregas)

- Rotas REST:
  - GET `/admin/{admin_id}` (detalhe), DELETE `/admin/{admin_id}` (remoção com salvaguardas).
  - PATCH `/admin/email` – altera e‑mail próprio; reinicia verificação e reenvio do código.
  - GET/POST `/admin/unlock`, GET `/admin/unlock/all` – consulta/remoção de lockouts.
  - GET `/admin/auth/verify-link`, POST `/admin/auth/verification-code` – verificação por link público e reenvio de código.
  - POST `/admin/auth/logout`, POST `/admin/auth/logout/all` – revogação de sessões.
- Infra e UX:
  - DTO/i18n centralizado para erros/mensagens.
  - Auditoria e métricas (mudanças sensíveis, contadores de erros/latências).
---

## Atualizações recentes

- Refatoração do handler: `pkg/httpapi/httpapi.go` concentra as rotas; `api/index.go` (package `handler`) delega para ele (compatível com Vercel).
- Rewrites no `vercel.json` habilitam `/healthz` e `/admin` sem prefixo `/api`.
- Banco em serverless: fallback automático para SQLite em `/tmp` quando `DATABASE_URL` não estiver definido (dados efêmeros). Para produção, configure Postgres.

Segmentação por domínio (concluída)

- Handlers de Admin migrados para `pkg/httpapi/admin_handlers.go` e entry points mantidos em `pkg/httpapi/handlers_admin_entry.go`.
- `pkg/httpapi/httpapi.go` mantém utilitários, init (DB/Redis/Email), JWT/ACL helpers e roteamento raiz; removeu corpos `_old` dos handlers de Admin.
- Rotas por domínio: Users (`router_users.go`/`users_handlers.go`), UsersSpaces (`router_spaces.go`/`spaces_handlers.go`), Tools (`router_tools_faciendum.go`, `router_tools_automata.go`).

### Novidades: OpenAPI e Tokens de API (integrações)

  - `GET /openapi.json` – expõe o arquivo `openapi.json` da raiz (público), para integração e documentação.
  - `POST /admin/mcp/token` – cria um Token de API (Bearer) vinculado ao administrador autenticado.
  - Request: `{ "name"?: string, "ttl_hours"?: number, "expires_at"?: RFC3339 }`
  - Response: `{ "success": true, "token_id": number, "token": string, "name"?: string, "expires_at"?: string }`
  - Expiração: por padrão segue `TOKEN_REFRESH_EXPIRE_SECONDS`. A expiração é "clampada" por `admins.expires_at` quando o plano não é `lifetime`.
  - Use o valor de `token` como `Authorization: Bearer <token>` em integrações (ex.: n8n). O token herda o mesmo `system_role` do administrador e respeita expiração/revogação.
  - Para integrar via MCP externo, consulte `docs/MCP_GUIDE.md`.
- Serviço de E-mail SMTP (`internal/services/email`) com templates embutidos (embed). Se o arquivo não existir no FS, usa o template embutido.
- Envio de e-mail síncrono em ambientes serverless (Vercel/Lambda) para garantir entrega antes do término da execução.
- Novas rotas e comportamentos:
  - `POST /admin` (criar admin): `password` opcional; gera senha de 8 dígitos; envia e-mail com senha, código e link de verificação.
  - `POST /admin/auth/verify-code/{code}` (pública) e `POST /admin/auth/verify` (compat.): ativam a conta ao validar código+senha.
  - `POST /admin/auth/password-recovery` (pública): redefine senha (8 dígitos), invalida verificação e envia código/link para verificação.
  - `PATCH /admin/password` (autenticada): altera a própria senha; valida senha atual; aplica política de senha; dispara e-mail de confirmação.
- Política de senha: modo estrito opcional via `PASSWORD_POLICY_STRICT=true` exige maiúscula, minúscula, número e caractere especial; por padrão, mínimo 8.
- Observabilidade: logs por requisição (método, caminho, status e duração) com `LOG_LEVEL`.
 - Limites configuráveis por env (usados quando Redis ativo):
   - `LOGIN_IP_LIMIT` (default 20), `LOGIN_IP_WINDOW_MINUTES` (default 5)
   - `LOGIN_USER_LIMIT` (default 20), `LOGIN_USER_WINDOW_MINUTES` (default 5)
   - `LOGIN_FAIL_LOCK_THRESHOLD` (default 5), `LOGIN_FAIL_LOCK_TTL_MINUTES` (default 15)
   - `RECOVERY_IP_LIMIT` (default 10), `RECOVERY_IP_WINDOW_MINUTES` (default 60)
   - `RECOVERY_EMAIL_LIMIT` (default 3), `RECOVERY_EMAIL_WINDOW_MINUTES` (default 15)
   - `VERIFY_CODE_TTL_HOURS` (default 24)
 - Segurança e Resiliência:
   - Redis (`REDIS_URL`) para rate limit/lockout (login: IP/usuário; recovery: IP/e‑mail).
   - Códigos de verificação com `expires_at` (24h) e checagem no uso.
   - Logs incluem User-Agent e bytes respondidos.
 - MFA por e‑mail (opcional):
   - `MFA_EMAIL_ENABLED` (true/false)
   - `MFA_CODE_TTL_MINUTES` (default 10)
   - `MFA_CODE_LENGTH` (default 6)
   - `MFA_MAX_ATTEMPTS` (default 5)

### `POST /admin/`

- Autorização: `Authorization: Bearer <ACCESS_TOKEN>`
- Corpo JSON:
  ```json
  {"email":"<email>","username":"<username>","password":"<senha>","system_role":"user|admin|guest"}
  ```
- Respostas:
  - 201 Created: `{"success":true,"admin_id":<id>,"username":"...","email":"...","system_role":"..."}`
  - 401/403 em caso de falta de token ou papel insuficiente
  - 409 em caso de `email`/`username` já existentes

Envio de e-mail: utiliza `ADMIN_CREATED_TEMPLATE_NAME` (default `admin_created.html`) no diretório `EMAIL_SERVER_TEMPLATE_DIR`.

Templates padrão adicionados em `template_email/`:
- `email_notifications.html` (genérico)
- `security_notifications.html` (segurança)
- `admin_created.html` (novo administrador)
