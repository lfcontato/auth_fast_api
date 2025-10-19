Arquivo: IMPLEMENTATION_GAPS.md
Resumo: Itens pendentes, riscos e sugestões de melhoria com base no código atual. Não altera comportamento — serve como guia de follow‑ups.

**Resumo Executivo**
- Núcleo pronto: login/refresh com rotação de refresh, criação/listagem de admins, verificação de conta (2 formas), recuperação de senha, planos de assinatura com expiração e clamp de tokens, envio de e‑mail com templates embutidos, compat Serverless (Vercel) e SQLite fallback em `/tmp`.
- Principais pendências: rotas de CRUD que constam no README mas não foram implementadas, políticas de segurança (rate limit/lockout), centralização de mensagens/códigos (DTO + i18n), auditoria/observabilidade, testes automatizados, e endurecimento do schema (checks/índices).

**1) Rotas e Regras de API (faltantes/planejadas)**
- Rotas documentadas no README ainda não implementadas:
  - GET `/admin/{admin_id}` (detalhe)
  - DELETE `/admin/{admin_id}` (remoção) com salvaguardas (sem autoexclusão/sem remover superior)
  - PATCH `/admin/email` (alterar e‑mail próprio; ao alterar, `is_verified = false` + gerar novo código)
  - Bloqueios/segurança: `/admin/unlock` (GET/POST) e `/admin/unlock/all`
  - Verificação pública por link: `/admin/auth/verify-link` (GET) e reenvio `/admin/auth/verification-code` (POST)
- Implementadas recentemente (ok):
  - PATCH `/admin/{id}/system-role` (hierarquia estrita; root pode todos)
  - PATCH `/admin/{id}/subscription-plan` (root pode qualquer plano; demais até `semiannual`)
  - PATCH `/admin/password` (alterar própria senha, valida senha atual; aplica política de senha; envia e‑mail de confirmação)

Sugestão:
- Implementar as rotas faltantes com as salvaguardas do README e padronizar envelope de resposta/códigos.

**2) Segurança e Resiliência (implementado nesta fase)**
- Rate limit e lockout:
  - Implementado com Redis (`REDIS_URL`).
  - Login: rate por IP (20/5min), por usuário (20/5min) e lockout por falhas (>=5/15min) com TTL de 15min.
  - Recuperação de senha: rate por IP (10/h) e por e‑mail (3/15min).
  - Verificação de conta: códigos agora expiram (`expires_at`), checados no momento do uso.
- Política de senha: IMPLEMENTADO (básico + modo estrito opcional)
  - Validação mínima (>=8) em entradas; modo estrito via `PASSWORD_POLICY_STRICT=true` exige maiúscula, minúscula, dígito e especial.
  - Geração automática: numérica de 8 dígitos (padrão) ou forte (12+ chars, todas as classes) quando estrito.
  - Aplicado em criação de admin, recuperação de senha e na rota de troca de senha própria (`PATCH /admin/password`).
- JWT e chaves:
  - Claims básicas sem `iss/aud/jti`. Algoritmo fixo HS256. Sugestão: adicionar `iss/aud`, `jti` (replay), suporte opcional a RS256 e estratégia de rotação de chaves.
- Revogação de sessões:
  - Há rotação por refresh, mas não há endpoints para logout único ou “revogar todas” (por admin). Sugestão: endpoints e índices por `family_id/admin_id`.
- Recuperação/verificação:
  - `admins_verifications` ganhou `expires_at`; inserções definem 24h de validade; verificação exige `expires_at > now`.
  - Throttling de recovery por IP/e‑mail conforme acima.
- E‑mail:
  - Envio síncrono em serverless (ok). Falta retry/backoff/poison‑queue. Sugestão: repetir com backoff; registrar bounce/reporting ao futuro.

**3) Domínio, Planos e Sessões**
- Mudança de plano e sessões ativas:
  - Clamp dos novos tokens já respeita `expires_at`. Sessões antigas continuam válidas até seu próprio `expires_at`. Sugestão: ao mudar plano, revogar sessões futuras a partir do novo limite (UPDATE em lote por `admin_id`).
- Seed root existente:
  - Ao encontrar root existente, hoje só força `is_verified = 1`. Sugestão: garantir também `subscription_plan = 'lifetime'` e `expires_at = NULL` (idempotente).
- Validações de entrada:
  - Criação de admin não valida `system_role` contra enum; PATCH de papel valida. Sugestão: validar no create também.

**4) Banco de Dados**
- Restrições e checks:
  - Não há CHECKs de domínio (enums) para `system_role`/`subscription_plan`. Sugestão: CHECKs em Postgres; em SQLite, validação na app.
- Índices:
  - Índice apenas em `admins_sessions_local.admin_id` e unicidade em `session_id/code/email/username`. Sugestão: índice para `refresh_token_hash`, `admins_verifications(admin_id, consumed_at)`, e possivelmente em `admins(expires_at)` para rotinas de limpeza/listagem.
- Limpeza de dados:
  - Sem rotina de expurgo de sessões/códigos antigos. Em serverless, pode ser “on‑read” ou job externo.
- Timezone/clock:
  - Postgres usa TIMESTAMPTZ, SQLite usa TIMESTAMP (sem tz). Sugestão: normalizar via UTC em app (já implícito) e documentar.

**5) Observabilidade e Auditoria**
- Logs:
  - Já há logs por requisição (método, caminho, status, duração). Sugestões:
    - Adicionar `User-Agent`, bytes respondidos (já medidos), e opcional `Request‑ID`/correlação.
    - Estruturar logs (JSON) para agregação.
- Métricas/tracing:
  - Não há métricas básicas (contadores/latência/erros) nem tracing. Sugestão: expor contadores simples; opcionalmente OpenTelemetry.

**6) Mensagens/DTO e i18n**
- O README menciona DTO e localização (`pt_br/en`), mas o código usa mapas inline por handler com `code/message`. Sugestão:
  - Centralizar catálogo de erros/códigos, com chaves e traduções.
  - Middleware para injetar `locale` e selecionar mensagem.

**7) Documentação e Testes**
- Documentos atualizados (HOWTOUSE, ADMINS, DATABASE, CONTEXTO) — bom estado.
- Falta suíte de testes:
  - Unit: auth service (hash, emissão, clamp), migrate/rebind, computeExpires.
  - Integração: login→refresh, create→verify, recovery→verify, patch de papel/plano (com regras de hierarquia e planos).
  - Smoke REST (VS Code REST Client já tem exemplos; expandir com novos endpoints).

Estado atual após revisão (resumo)

- Implementado: rate/lock com Redis, expiração de códigos de verificação, política de senha (modo estrito opcional), PATCH `/admin/password`, PATCH `/admin/{id}/system-role`, PATCH `/admin/{id}/subscription-plan`, verificação por código (URL/body), recuperação com throttling, criação/listagem de admins.
- Pendente: GET/DELETE `/admin/{admin_id}`, PATCH `/admin/email`, governança `/admin/unlock` (GET/POST, `/admin/unlock/all`), verificação por link público e reenvio de código, logout(s), DTO/i18n, auditoria e métricas, ampliação da suíte de testes.

**8) Outras melhorias**
- CORS para uso com frontends (se necessário) — hoje não há configuração específica.
- Sanitização de `username/email` (normalização, limites, set de caracteres, tamanho máximo, e‑mail RFC).
- Templates de e‑mail dedicados por fluxo (ex.: `password_recovery.html`) — hoje o recovery reutiliza conteúdo próximo do criado.
- Consistência de envelopes/códigos HTTP (ex.: 502 no e‑mail já é usado; alinhar com catálogo de erros consolidado).

**Referências (arquivos importantes)**
- Handlers HTTP (rotas e lógica): `pkg/httpapi/httpapi.go`
- Serviço de Autenticação: `internal/services/auth/service.go`
- Migrações/Drivers: `internal/db/migrate.go`, `internal/db/rebind.go`, `internal/db/db.go`, `internal/db/dsn.go`
- Modelos de domínio: `internal/domain/models.go`
- E‑mail (SMTP + templates embutidos): `internal/services/email/`
- Configuração: `internal/config/config.go`
