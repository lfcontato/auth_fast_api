Arquivo: DATABASE.md
Resumo: Esquema de dados e regras de persistência usadas pela API (SQLite/Postgres), incluindo colunas, restrições, planos de assinatura e como os tokens respeitam expiração de conta.

**Visão Geral**
- Banco suportado: SQLite (modernc) e Postgres (pgx).
- Migrações automáticas em runtime criam tabelas e tentam adicionar colunas novas quando ausentes.
- Em serverless (Vercel/Lambda), se `DATABASE_URL` estiver vazio, a API usa SQLite em `/tmp/auth_fast_api.db` (dados efêmeros).

**Tabelas**
- Admins
  - Finalidade: contas de administradores, verificação e assinatura.
  - Colunas principais:
    - `id` (PK)
    - `email` (único)
    - `username` (único)
    - `password_hash` (bcrypt)
    - `system_role` (`guest|user|admin|root`)
    - `subscription_plan` (`minute|hourly|daily|trial|monthly|semiannual|annual|lifetime`) – default `monthly` (seed do root = `lifetime`)
    - `expires_at` (timestamp; `NULL` para `lifetime`)
    - `is_verified` (boolean)
    - `owner_id` (admin criador; opcional)
    - `created_at`, `updated_at`
  - Índices/únicos: `email` único, `username` único.
  - Regras de negócio:
    - Root seed: criado/ativado com `subscription_plan=lifetime`, `expires_at=NULL`.
    - Criação sem plano informado usa `monthly` e calcula `expires_at` (+1 mês).
    - Atualização de plano recalcula `expires_at`:
      - `lifetime`: `NULL`
      - `annual`: +1 ano; `semiannual`: +6 meses; `monthly`: +1 mês; `trial`: +7 dias; `daily`: +1 dia; `hourly`: +1 hora; `minute`: +5 minutos
    - Alteração de `system_role` respeita hierarquia strict (exceto `root`, que pode tudo).

- Admins Sessions Local
  - Finalidade: ciclo de vida de refresh tokens por sessão.
  - Colunas: `id`, `admin_id` (FK), `session_id` (único), `family_id`, `refresh_token_hash` (sha256 hex), `expires_at`, `revoked_at`, `revoked_reason`, `created_at`.
  - Regras: cada login/refresh cria sessão nova; refresh anterior é revogado (rotação).

- Admins Verifications
  - Finalidade: códigos de verificação (ativação e recuperação de senha).
  - Colunas: `id`, `admin_id` (FK), `code` (64 chars hex, único), `created_at`, `consumed_at`.
  - Regras: somente códigos com `consumed_at IS NULL` são válidos; ao verificar, marca `admins.is_verified=1` e consome o código.

**Planos e Expiração**
- Duração por plano (cálculo a partir de “agora”):
  - `minute`: +5 min
  - `hourly`: +1 h
  - `daily`: +1 dia
  - `trial`: +7 dias
  - `monthly`: +1 mês
  - `semiannual`: +6 meses
  - `annual`: +1 ano
  - `lifetime`: `NULL`
- Concessão de plano:
  - `root` pode definir qualquer plano.
  - Outros admins podem definir até `semiannual` (inclusive).

**Tokens e Restrições**
- Login/refresh são negados se o plano estiver expirado (exceto `lifetime`).
- `access_token.exp` e `admins_sessions_local.expires_at` são “limitados” para não ultrapassar `admins.expires_at` (exceto `lifetime`).
- Login exige `is_verified=1`.

**Compatibilidade e Migração**
- Criação das tabelas com `CREATE TABLE IF NOT EXISTS` para SQLite/Postgres.
- Atualização best‑effort para colunas novas (ex.: `subscription_plan`, `expires_at`) com `ALTER TABLE`; erros de “coluna já existe” são ignorados.

**Rotas Relacionadas**
- Assinatura
  - `PATCH /admin/{admin_id}/subscription-plan`: atualiza plano e recalcula `expires_at`.
- Papel
  - `PATCH /admin/{admin_id}/system-role`: altera `system_role` sob regra de hierarquia estrita.
- Verificação
  - `POST /admin/auth/verify-code/{code}` ou `POST /admin/auth/verify`: confirma conta (requer `password`).
- Sessões
  - `POST /admin/auth/token`: login
  - `POST /admin/auth/token/refresh`: rotação de tokens

**Referências de Código**
- Esquema e migração: `internal/db/migrate.go`
- Modelos: `internal/domain/models.go`
- Regras de login/refresh e clamp de expiração: `internal/services/auth/service.go`
- Handlers HTTP (criar admin, verificação, recuperação, patch de plano/papel): `pkg/httpapi/httpapi.go`

