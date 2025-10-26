
# Prompt de Desenvolvimento Contínuo (Contexto Permanente)

> **Use sempre este prompt ao adicionar/alterar funcionalidades.**  
> Linguagem: **Português (Brasil)**.  
> Objetivo: **Segmentar o código por domínio**, manter **README.md atualizado** (com checklists do que foi implementado/pendente/sugestões) e **gerar documentação HOWTOUSE** por funcionalidade automaticamente.

---

## 1) Diretriz central

- **Cada nova funcionalidade** deve ser isolada em **um domínio** (DDD leve).
- **Não** quebre outras rotas/domínios: evite importações cruzadas diretas; exponha **interfaces** (ports) e **serviços** (adapters).
- Se a funcionalidade **pertencer a um domínio existente**, atualize **apenas** esse domínio.
- Sempre que criar/alterar algo, **atualize**:
  1. `README.md` → com *Checklist* (feito, pendente, sugestões).
  2. `docs/HOWTOUSE_{nome_da_funcionalidade}.md` → guia de uso com exemplos (cURL/HTTP), requisitos e observações.
- **Nunca** misture DTOs/entidades entre domínios sem um *mapper* explícito.
- **Tratamento de erros padronizados** (códigos, mensagens i18n-friendly) e **logs estruturados** por domínio.

---

## 2) Convenções de estrutura (exemplo)

```
/cmd/server                          # bootstrap
/pkg
  /{dominio}
    /entity                          # entidades do domínio
    /dto                             # inputs/outputs (API-safe)
    /repo                            # interfaces de persistência
    /service                         # regras de negócio
    /http                            # handlers/routers do domínio
    /usecase                         # orquestração de casos de uso
    /errors                          # erros do domínio
    /mapper                          # conversão entity<->dto
/internal
  /platform/{db,cache,mailer,...}    # implementações técnicas
/docs
  HOWTOUSE_{funcionalidade}.md       # um por funcionalidade
README.md
```

**Regra de imports:** `http` → chama `usecase/service` → usa `repo (interface)` → implementado em `internal/platform`.  
**Proibido:** `http` de um domínio importar `service` de outro domínio.

---

## 3) Regras ao criar **nova funcionalidade**

1. **Nomeie o domínio** (novo ou existente) e descreva a responsabilidade única.
2. **Crie/atualize** pastas do domínio conforme convenções.
3. **Defina DTOs** de entrada/saída (documente campos, defaults e validações).
4. **Implemente casos de uso** em `usecase` chamando `service`, sem dependência de tecnologia.
5. **Erros do domínio** com códigos estáveis (`AUTH_401_005`, etc.).
6. **Handlers/Rotas** em `http` consumindo os DTOs; **não** acople à camada de persistência.
7. **Testes** mínimos: unitários no `service` e integração leve no `http` (feliz e erros).
8. **Documente**: crie `docs/HOWTOUSE_{funcionalidade}.md` (modelo abaixo).
9. **Atualize README.md** (modelo de checklist abaixo).

---

## 4) Atualização obrigatória do **README.md**

> Ao finalizar a tarefa, **atualize o README** acrescentando/ajustando:

- **Visão geral** do sistema (breve).
- **Mapa de domínios** (lista e responsabilidades).
- **Endpoints principais** e link para `openapi.json` se houver.
- **Como rodar localmente** e variáveis `.env` importantes.
- **Checklists**:
  - **Implementado** (com data e hash opcional).
  - **Pendente** (prioridade/critério de aceite).
  - **Sugestões/Ideias** (curtas, viáveis).

### Modelo de bloco no final do README

```markdown
## Histórico de Implementações e Backlog

### ✅ Implementado
- [x] {YYYY-MM-DD} – {Funcionalidade} – Domínio: {dominio} – {breve descrição}
- [x] ...

### 🧩 Pendente
- [ ] {Funcionalidade pendente} – Critério de aceite: {...}
- [ ] ...

### 💡 Sugestões
- [ ] {Ideia curta e objetiva}
- [ ] ...
```

---

## 5) Modelo de **docs/HOWTOUSE_{funcionalidade}.md**

```markdown
# HOWTOUSE – {Nome da Funcionalidade}

**Domínio:** {dominio}
**Resumo:** {o que resolve, regras de uso e limites}
**Pré‑requisitos:** {env, seeds, serviços externos...}

## Exemplos (cURL/HTTP)
```bash
# Exemplo 1
curl -i -X {GET|POST|...} http://localhost:8080/{rota}   -H 'Content-Type: application/json'   -d '{ "campo": "valor" }'
```

## Códigos de Resposta
- 200 OK – ...
- 400 AUTH_400_001 – JSON inválido
- 401 AUTH_401_00X – ...
- ...

## Observações
- {notas de segurança, limites, warnings}
```

---

## 6) Padrões de qualidade

- **Logs** estruturados por domínio (trace_id, rota, domínio, severidade).
- **Rate limit** e **CORS/segurança** prontos para produção quando integrar com front.
- **Mensagens** de erro/documentação em **pt-BR** (facilitar suporte).
- **OpenAPI** atualizado após novas rotas.
- **Commit message** clara: `feat(domain): ...`, `fix(domain): ...`, `docs(...): ...`

---

## 7) Saída esperada deste prompt (quando eu pedir algo novo)

Quando eu solicitar uma nova funcionalidade/ajuste, **entregue**:
1. **Arquivos/trechos** por domínio (entity/dto/service/usecase/http/errors/mapper).
2. **README.md patch** (apêndice no final com o bloco “Histórico de Implementações e Backlog”).  
3. **`docs/HOWTOUSE_{nome}.md`** com exemplos cURL.
4. **Notas de migração** (se alterar contratos/DB).

---

## 8) Exemplo de guia (Administradores – Rotas + cURL)

> **Use este exemplo como referência de HOWTOUSE e README**. Ajuste nomes/rotas conforme seu projeto.

### Guia de Administradores (Rotas + cURL)

Use estes exemplos para validar os fluxos de administrador em ambiente local.

**Pré‑requisitos**
- Banco de dados via `DATABASE_URL` (ou SQLite padrão `database_test.db`).
- `SECRET_KEY` definida.
- Serviço local: `go run ./cmd/server` (escuta em http://localhost:8080).
- Opcional (e‑mail): configurar SMTP no `.env` para envio real de e‑mails.

**Base local**
- Todas as chamadas abaixo usam `http://localhost:8080`.

**Seed do administrador root**
- Defina no `.env`: `ROOT_AUTH_USER`, `ROOT_AUTH_EMAIL`, `ROOT_AUTH_PASSWORD`.
- Ao iniciar o servidor, o root é criado automaticamente, se não existir.

#### Rotas e cURL (amostra)

- **Healthcheck**
  - GET `/healthz`
  - `curl -i http://localhost:8080/healthz`
  - Resposta (200):
    ```json
    { "ok": true, "service": "auth_fast_api", "status": "healthy" }
    ```

- **Raiz (opcional)**
  - GET `/`
  - `curl -i http://localhost:8080/`
  - Resposta (200):
    ```json
    { "ok": true, "service": "auth_fast_api", "version": "0.1.0", "endpoints": ["/healthz", "/admin/auth/token", "/admin/auth/token/refresh", "/admin/auth/password-recovery", "/admin (GET)"] }
    ```

- **OpenAPI (esquema)**
  - GET `/openapi.json`
  - `curl -s http://localhost:8080/openapi.json | jq .info`

- **Login (obter tokens)**
  - POST `/admin/auth/token`
  - Body: `{ "username": "<ROOT_AUTH_USER>", "password": "<ROOT_AUTH_PASSWORD>" }`
  - Regra: somente `is_verified = 1` loga; não verificado → `401`.
  - `curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"seu_user","password":"sua_senha"}'`
  - Dica:
    ```bash
    TOKENS=$(curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"seu_user","password":"sua_senha"}')
    ACCESS=$(echo "$TOKENS" | jq -r .access_token)
    REFRESH=$(echo "$TOKENS" | jq -r .refresh_token)
    ```
  - Resposta (200):
    ```json
    { "success": true, "access_token": "<JWT>", "refresh_token": "<REFRESH>" }
    ```

- **MFA por e‑mail (quando habilitado)**
  - Ative com `MFA_EMAIL_ENABLED=true`.
  - Fluxo em 2 passos com `mfa_tx` e `/admin/auth/mfa/verify`.

- **Refresh de token**
  - POST `/admin/auth/token/refresh`
  - Body: `{ "refresh_token": "<REFRESH_TOKEN>" }`

- **Criar Token de API (PAT) para integrações (ex.: n8n)**
  - POST `/admin/mcp/token`
  - Auth: `Authorization: Bearer <ACCESS_TOKEN>`
  - Body: `{ "name": "n8n", "ttl_hours": 720 }`
  - Observações: PAT herda permissões do criador; expiração padrão usa `TOKEN_REFRESH_EXPIRE_SECONDS` (se não informada).

- **Criar novo administrador**
  - POST `/admin` (com regras de hierarquia e defaults).

- **Listar administradores (autenticada)**
  - GET `/admin` (offset/limit).

- **Verificação de conta, recuperação de senha, alterações de plano/papel/senha** (exemplos completos conforme seu projeto).

### Backlog de rotas (a implementar) – Exemplo

- GET `/admin/{admin_id}` – detalhes.
- DELETE `/admin/{admin_id}` – remoção com hierarquia.
- PATCH `/admin/email` – reinicia verificação.
- Bloqueios/segurança: `/admin/unlock`, `/admin/unlock/all`.
- Verificação via link público e reenvio de código.
- Sessões: logout atual e *logout all*.

### Próximos Passos (Checklist – exemplo)

- [x] Login/Refresh de Admin (`/admin/auth/token`, `/admin/auth/token/refresh`).
- [x] MFA por e‑mail (opcional) com transação e limitação.
- [x] Verificação de conta (corpo e por URL).
- [x] Recuperação de senha (gera nova senha e re-verificação).
- [x] Listagem e criação de admins (`GET/POST /admin`).
- [x] Alterar plano (`PATCH /admin/{id}/subscription-plan`).
- [x] Alterar papel (`PATCH /admin/{id}/system-role`).
- [x] Alterar própria senha (`PATCH /admin/password`).
- [x] Tokens de API (PAT) – criação/uso via Bearer.
- [x] Segmentação por domínio concluída (handlers movidos para `pkg/httpapi/admin_handlers.go`).
- [ ] Sessões: listagem/revogação (`sid`/`family_id`).
- [ ] PAT: listagem/revogação, escopos, limites e auditoria.
- [ ] Auditoria e rate limit por rota.
- [ ] DTO/i18n padronizados (pt-BR/en-US).
- [ ] CORS/headers de segurança para front.
- [ ] Paginação/filtros extras.
- [ ] Testes de integração e cobertura de erros.

---

## 9) Como responder quando eu pedir “crie X”

1. Diga o **domínio** alvo.
2. Liste **arquivos/trechos** com caminhos e resumos de funções.
3. Traga o **patch do README** (apenas o bloco a anexar).
4. Entregue `docs/HOWTOUSE_{X}.md` completo.
5. Inclua **exemplos cURL/HTTP** prontos para copiar/colar.
6. Se algo for ambíguo, **assuma defaults sensatos** e documente.

---

> **Este documento é o contrato de contribuição do projeto.**  
> Sempre reaplique este contexto nos próximos pedidos para evitar repetição.
