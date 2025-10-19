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


---
Data: 2025-10-19

Resumo das mudanças implementadas neste ciclo:

Infra/Arquitetura
- Refatoração do handler HTTP para `pkg/httpapi/httpapi.go` (público). A função serverless em `api/index.go` (package `handler`) apenas delega para este handler.
- Rewrites no `vercel.json` para aceitar `/healthz` e `/admin` sem prefixo `/api`.
- `.vercelignore` adicionado para evitar upload de `node_modules` e artefatos locais que quebravam o build Go na Vercel.
- `.gitignore` ampliado (binários Go, node_modules, editores etc.).
- Fallback de banco em ambiente serverless: se `DATABASE_URL` estiver vazio em Vercel/Lambda, usa SQLite em `/tmp/auth_fast_api.db` (área gravável). Mantém portabilidade; para produção real, recomenda-se Postgres.
- Logs de requisição em todas as rotas (método, caminho, status, duração) via `statusWriter` com `LOG_LEVEL` (DEBUG/INFO/WARN/ERROR).
 - Logs agora incluem User-Agent e bytes respondidos.

E-mail
- Serviço SMTP (`internal/services/email`) agora suporta templates embutidos (embedded) via `template_email/embed.go`. Se o arquivo não estiver no filesystem, carrega do FS embutido.
- Em ambiente serverless, envios de e-mail passaram a ser síncronos (antes eram goroutines após a resposta), garantindo que o e-mail seja enviado antes do término da execução.
- Fallbacks de remetente: se `EMAIL_FROM_*` não forem definidos, usa `EMAIL_SERVER_USERNAME`/`EMAIL_SERVER_NAME`.

 Rotas implementadas/ajustadas
- `POST /admin` (criar admin):
  - Aceita `/admin` e `/admin/`.
  - Campo `password` opcional; se vazio, gera senha numérica de 8 dígitos.
  - Envia e-mail ao novo admin com senha inicial, código de verificação e link de verificação.
- Verificação de conta:
  - `POST /admin/auth/verify-code/{code}` (recomendado): recebe apenas `password` no corpo.
  - `POST /admin/auth/verify` (compatibilidade): recebe `code` e `password` no corpo.
  - Nova tabela `admins_verifications` para armazenar e consumir códigos.
- Recuperação de senha:
  - `POST /admin/auth/password-recovery`: gera nova senha (8 dígitos), marca `is_verified=0`, cria novo código e envia e-mail com senha e link de verificação.
 - Alteração de senha própria:
   - `PATCH /admin/password`: valida senha atual; aplica política de senha; e-mail de confirmação.

- Planos e papéis:
  - `PATCH /admin/{id}/subscription-plan`: atualiza plano; recalcula `expires_at`; tokens passam a respeitar o novo limite (clamp em login/refresh).
  - `PATCH /admin/{id}/system-role`: altera papel sob hierarquia estrita (root pode todos).

- Senhas (política e alteração):
  - Política de senha implementada com modo estrito opcional (`PASSWORD_POLICY_STRICT`).
  - `PATCH /admin/password`: altera a senha do próprio admin; valida senha atual; aplica política e envia e-mail de confirmação.

Templates de e-mail
- `template_email/admin_created.html` atualizado para incluir `Senha inicial`, `Código de verificação` e botão com `VerifyURL`.

Documentação atualizada
- `USERS.md`: verificação de conta (com `{code}` na URL) e exemplo cURL; observações e fluxo típico frontend → backend.
- `HOWTOUSE.md`: bases de URL, rotas atuais e exemplos de login/refresh/criar admin; será ampliado com verificação e recuperação (ver patch abaixo).

Observações de deploy (Vercel)
- `api/index.go` deve ser `package handler` com `func Handler(http.ResponseWriter, *http.Request)`. O build remoto exige isso.
- Rewrites configurados para aceitar rotas sem `/api`.
- Em logs de produção, agora aparece: `[INFO]  METHOD /path -> STATUS (duration)`.
 - Redis suportado via `REDIS_URL` para rate limit/lockout.

Segurança e Resiliência
- Rate limit e lockout implementados com Redis:
  - Login: IP (20/5min), usuário (20/5min), lock de falhas (>=5/15min).
  - Recovery: IP (10/h), e‑mail (3/15min).
- Códigos de verificação passam a expirar (24h) — coluna `expires_at` e checagem no uso.
 - MFA por e‑mail: login em 2 etapas quando `MFA_EMAIL_ENABLED=true` (retém tokens no Redis até validação do código em `/admin/auth/mfa/verify`).
Planejado/próxima entrega
- `PATCH /admin/{admin_id}/system-role`: rota autenticada para alterar o `system_role` de outro administrador sob regra de hierarquia:
  - Somente é permitido alterar administradores com papel estritamente inferior ao do solicitante.
  - O novo papel também deve ser estritamente inferior ao do solicitante.
  - Exceção: `root` pode alterar qualquer papel (inclusive promover/demover para `root`).

Pendências mapeadas após revisão

- Rotas REST ainda não implementadas (constam no README):
  - GET `/admin/{admin_id}` – detalhe; DELETE `/admin/{admin_id}` – remoção com salvaguardas.
  - PATCH `/admin/email` – altera e‑mail próprio, reinicia verificação e gera novo código.
  - GET/POST `/admin/unlock`, GET `/admin/unlock/all` – governança de bloqueios/lockouts.
  - GET `/admin/auth/verify-link`, POST `/admin/auth/verification-code` – verificação por link público e reenvio.
  - POST `/admin/auth/logout`, POST `/admin/auth/logout/all` – revogação de sessão atual e de todas as sessões.
- Padrão de mensagens/DTO com i18n – centralizar catálogo de erros/códigos e traduções.
- Auditoria/métricas – registrar mudanças sensíveis (papel, plano, senha) e expor métricas básicas.
