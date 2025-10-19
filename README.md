# 🚀 API de Autenticação e Autorização (Auth_Fast_API) - Versão Completa

Este é o **prompt de sistema final** para a construção da API de autenticação e autorização (`Auth_Fast_API`). O objetivo é estruturar o modelo de dados, as regras de negócio e a lógica de autorização, sem gerar código.

Voce deve manter um arquivo de contexto, chamado CONTEXTO.md que vai adicionar sempre o prompt anterior, mantendo com todas as alterações feitas no programa e as novas funcionalidades.

no inicio de cada arquivo deve conter o caminho e o resumo de que faz o arquivo
antes de cada função deve descrever o que ela faz.

O sistema deve:
* Persistir dados em **PostgreSQL ou SQLite**.
* Receber variáveis de configuração via **arquivo `.env`**.
* Implementar padrão **DTO** para mensagens de sistema com localização (`pt_br.json` e `en.json`).
* Seguir uma arquitetura limpa/modular (conforme sugerido na estrutura de pastas em `internal/`).

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

---

## 4. Gestão de Bloqueios e Segurança

| Endpoint | Método | Resumo da Funcionalidade | Requisitos de Acesso |
| :--- | :--- | :--- | :--- |
| **`/admin/unlock`** | `POST` | **Desbloquear Administrador.** Remove bloqueios temporários (por tentativas malsucedidas) de uma conta alvo (via `email`). | Exige `system_role` (`root` ou `admin`) superior para intervir em outra conta. |
| **`/admin/unlock`** | `GET` | **Consultar Bloqueios do Administrador.** Retorna o estado de bloqueio (`is_blocked_login`, `is_blocked_password`) e tempo de *retry* associado a um `email`. | Exige `system_role` (`root` ou `admin`) suficiente para consulta. |
| **`/admin/unlock/all`** | `GET` | **Listar Bloqueios Ativos.** Retorna todos os bloqueios temporários de login/senha registrados. | Requer autenticação (geralmente restrito a `root` ou `admin`). |
| **`/admin/password-recovery`** | `POST` | **Disparar Recuperação (Admin Controlada).** Gera e envia o token de recuperação para o admin informado (Uso interno/suporte). | Requer **autenticação**. Respeita *rate limit*. |
---

## Atualizações recentes

- Serviço de E-mail SMTP implementado em `internal/services/email` (compatível com STARTTLS e SSL/TLS). Configuração via `.env` (`EMAIL_SERVER_*`, `EMAIL_FROM_*`, `EMAIL_TEMPLATE_NAME`, `SECURITY_TEMPLATE_NAME`, `ADMIN_CREATED_TEMPLATE_NAME`).
- Endpoint implementado: `POST /admin/` (criar administrador) – requer Bearer token de um administrador com papel superior ao alvo. Ao criar, dispara e-mail ao novo administrador usando o template configurado (padrão: `admin_created.html`).
 - Logging de requisições e eventos (login, refresh, criação de admin) controlado por `LOG_LEVEL` (DEBUG/INFO/WARN/ERROR).

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
