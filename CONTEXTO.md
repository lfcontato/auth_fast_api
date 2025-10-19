Arquivo: CONTEXTO.md
Resumo: Histórico de prompts e alterações aplicadas ao projeto. Mantém o contexto de decisões e funcionalidades adicionadas.

---
Data: 2025-10-18

Prompt do usuário:
"criar um sistema"

Diretrizes relevantes (README):
- Manter arquivo de contexto (CONTEXTO.md) com prompts anteriores, alterações e novas funcionalidades.
- No início de cada arquivo, incluir caminho e resumo do que o arquivo faz.
- Antes de cada função, descrever o que ela faz.

Alterações realizadas neste ciclo:
- Scaffold do ponto de entrada Serverless para Vercel em `api/index.go` com rotas básicas: `/`, `/healthz`, stubs de `/admin/auth/token` e `/admin/auth/token/refresh`.
- Criação do pacote de configuração em `internal/config/config.go` para carregar variáveis de ambiente.
- Criação de handlers base de autenticação em `internal/handlers/admin_auth.go` (stubs com DTOs).
- Criação de utilitários JWT stubs em `internal/auth/jwt.go` (interfaces e erros `not implemented`).
- Criação do stub de conexão com banco em `internal/db/db.go`.

Atualizações adicionais nesta entrega:
- Implementado conector DB com suporte a `sqlite` (modernc, puro Go) e `pgx` (Postgres), com parser de `DATABASE_URL` (`internal/db/dsn.go`).
- Adicionadas migrações mínimas para `admins` e `admins_sessions_local` (`internal/db/migrate.go`).
- Serviço de autenticação com login, geração de Access (JWT HS256) e Refresh (random/sha256), além de refresh/rotação (`internal/services/auth/service.go`).
- `api/index.go` agora inicializa DB + migrações, faz seed do usuário root a partir de env e expõe endpoints funcionais:
  - `POST /admin/auth/token` (login por username/password)
  - `POST /admin/auth/token/refresh` (rotação de refresh)
- Execução de `go mod tidy` e build validado com sucesso.

Novas funcionalidades implementadas agora:
- Serviço de E-mail SMTP com templates HTML em `internal/services/email` (modos: `STARTTLS`, `SSL/TLS` e `NONE`). Configurações adicionadas em `internal/config/config.go` lendo `.env`.
- Endpoint protegido `POST /admin/` para criação de administradores:
  - Requer Bearer token válido; somente um administrador com `system_role` superior ao alvo pode criar.
  - Ao criar, envia e-mail ao novo administrador usando o template `ADMIN_CREATED_TEMPLATE_NAME` (default `admin_created.html`).
  - Implementação em `api/index.go` (`adminCreateHandler`).

Templates de e-mail padrão adicionados:
- `template_email/email_notifications.html` (notificação genérica)
- `template_email/security_notifications.html` (alertas de segurança)
- `template_email/admin_created.html` (novo administrador)

Observabilidade:
- Adicionado nível de logs controlado por `LOG_LEVEL` no `.env` (DEBUG/INFO/WARN/ERROR).
- Implementado logging de requisições (método, caminho, status, duração) e de eventos (login, refresh, criação de admin) em `api/index.go`.

Documentação:
- Criado `USERS.md` com o guia de criação de contas (administradores implementado; usuários comuns planejados), passos práticos e referências às rotas e templates.

Documentação para consumo da API:
- Criado `HOWTOUSE.md` com instruções completas de uso (bases de URL, autenticação, esquema de tokens JWT, formato de erros, exemplos curl e REST Client, configuração de ambiente, endpoints atuais e planejados, boas práticas).

Próximos passos sugeridos:
- Mapear mais endpoints do OpenAPI para handlers reais (lista, criação e detalhes de admins).
- Implementar serviço de autenticação (hash de senha, verificação, emissão JWT) e persistência.
- Escolher driver e DSN para o banco (Postgres ou SQLite) e implementar `db.Connect`.
- Adicionar mensagens padronizadas e localização (pt_br/en) conforme DTO.

Atualização de testes (REST Client):
- Adicionados arquivos `.http` em `tests/` para testar localmente via VS Code REST Client:
  - `tests/health.http` – GET `/healthz`.
  - `tests/auth.http` – POST login e POST refresh, usando `{{$dotenv ROOT_AUTH_USER}}` e `{{$dotenv ROOT_AUTH_PASSWORD}}` do `.env`.
  - `tests/README.md` – instruções de uso.
