Arquivo: docs/MCP_GUIDE.md
Resumo: Guia prático para integrar um servidor MCP externo a esta API. Inclui exemplos cURL de todos os recursos atuais e orientações de configuração. Deve ser mantido atualizado a cada nova funcionalidade.

# MCP Guide (integração externa)

Objetivo
- Centralizar exemplos cURL e instruções para que um servidor MCP externo (em outro projeto) consiga consumir todos os recursos desta API.
- Não há servidor MCP embutido aqui. Rode seu MCP em outro projeto/ambiente e aponte para esta API (Vercel ou local).

Observações importantes
- Vercel executa a API HTTP (rotas sob `/api`), não processos por stdio. Execute o MCP externamente e use a base da API da Vercel.
- Token de API (PAT) é criado via `POST /admin/mcp/token` e pode ser usado como `Authorization: Bearer <token>` nas chamadas — ideal para integrações e MCP externo.

## Bases de URL

- Local (dev): `http://localhost:8080`
- Vercel (prod): `https://<seu-projeto>.vercel.app/api`

Dica: nos exemplos abaixo, ajuste a variável `BASE` conforme o ambiente.

```bash
# Local
export BASE="http://localhost:8080"

# Produção (Vercel)
# export BASE="https://<seu-projeto>.vercel.app/api"
```

## Autenticação e Tokens

Tipos aceitos no header `Authorization: Bearer ...`:
- Access Token (JWT) obtido no login
- Token de API (opaco, PAT) criado via `/admin/mcp/token`

Variáveis úteis para os exemplos:
```bash
# Após login, defina (exemplos abaixo mostram como obter):
export ACCESS="<JWT_ACCESS_TOKEN>"
export REFRESH="<REFRESH_TOKEN>"

# Após criar um PAT:
export PAT="<API_TOKEN>"
```

## Endpoints: cURL de referência

### Health Check
```bash
curl -sS -X GET "$BASE/healthz"
```

### OpenAPI (Esquema)
```bash
curl -sS -X GET "$BASE/openapi.json" -H 'Accept: application/json'
```

### Login de Administrador (obter tokens)
```bash
curl -sS -X POST "$BASE/admin/auth/token" \
  -H 'Content-Type: application/json' \
  -d '{"username":"<ROOT_AUTH_USER>","password":"<ROOT_AUTH_PASSWORD>"}'

# Dica: guardar variáveis ACCESS e REFRESH
TOKENS=$(curl -sS -X POST "$BASE/admin/auth/token" -H 'Content-Type: application/json' \
  -d '{"username":"<ROOT_AUTH_USER>","password":"<ROOT_AUTH_PASSWORD>"}')
export ACCESS=$(echo "$TOKENS" | jq -r .access_token)
export REFRESH=$(echo "$TOKENS" | jq -r .refresh_token)
```

### MFA por e‑mail (quando habilitado)
```bash
# Passo 1 – inicia login (retorna 202 + mfa_tx)
curl -sS -X POST "$BASE/admin/auth/token" \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","password":"<pass>"}'

# Passo 2 – verifica código recebido
curl -sS -X POST "$BASE/admin/auth/mfa/verify" \
  -H 'Content-Type: application/json' \
  -d '{"mfa_tx":"<DO_PASSO_1>","code":"123456"}'
```

### Renovação de Tokens (Refresh)
```bash
curl -sS -X POST "$BASE/admin/auth/token/refresh" \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"'$REFRESH'"}'
```

### Criar Token de API (PAT)
```bash
# Requer ACCESS válido (JWT)
curl -sS -X POST "$BASE/admin/mcp/token" \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"name":"n8n","ttl_hours":720}'

# Guardar o PAT retornado
export PAT=$(curl -sS -X POST "$BASE/admin/mcp/token" \
  -H "Authorization: Bearer $ACCESS" -H 'Content-Type: application/json' \
  -d '{"name":"n8n","ttl_hours":720}' | jq -r .token)
```

### Listar Administradores
```bash
# Com ACCESS (JWT)
curl -sS -X GET "$BASE/admin?offset=0&limit=20" -H "Authorization: Bearer $ACCESS"

# Com PAT (token opaco)
curl -sS -X GET "$BASE/admin?offset=0&limit=20" -H "Authorization: Bearer $PAT"
```

### Criar Administrador
```bash
curl -sS -X POST "$BASE/admin" \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{
        "email":"novo@dominio.com",
        "username":"novo_admin",
        "password":"SenhaForte123",
        "system_role":"user",
        "subscription_plan":"monthly"
      }'
```

### Alterar Papel (system_role)
```bash
curl -sS -X PATCH "$BASE/admin/123/system-role" \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"system_role":"admin"}'
```

### Alterar Plano (subscription_plan)
```bash
curl -sS -X PATCH "$BASE/admin/123/subscription-plan" \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"subscription_plan":"monthly"}'
```

### Verificação de Conta
```bash
# Via código na URL (recomendado)
curl -sS -X POST "$BASE/admin/auth/verify-code/<code>" \
  -H 'Content-Type: application/json' \
  -d '{"password":"<senha_inicial>"}'

# Compatibilidade (corpo)
curl -sS -X POST "$BASE/admin/auth/verify" \
  -H 'Content-Type: application/json' \
  -d '{"code":"<64_hex>","password":"<senha_inicial>"}'
```

### Recuperação de Senha (e redefinição via e‑mail)
```bash
curl -sS -X POST "$BASE/admin/auth/password-recovery" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@dominio.com"}'
```

### Alterar Própria Senha (autenticada)
```bash
curl -sS -X PATCH "$BASE/admin/password" \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"<atual>","new_password":"<nova_senha>"}'
```

## Boas práticas para seu MCP externo

- Transporte/execução: rode seu servidor MCP fora da Vercel, apontando `BASE` para a URL da API (local ou Vercel `/api`).
- Autorização: prefira usar PAT para agentes/integrações. Para flows de usuário, use JWT e faça refresh quando 401 por expiração.
- Segurança de tokens: armazene PAT/ACCESS/REFRESH de forma segura; PAT é exibido apenas na criação.
- Expiração/planos: tokens respeitam `subscription_plan` (clamp por `expires_at` quando não‑lifetime).
- Rate limiting/lockout: respeite limites (especialmente em login e recovery) e trate 429/401/403.
- OpenAPI: consuma `$BASE/openapi.json` para mapear endpoints e gerar clients automáticos quando conveniente.

## Manutenção deste guia

- A cada nova funcionalidade/endpoint da API, adicione o(s) exemplo(s) cURL correspondentes aqui.
- Se rotas forem renomeadas/movidas, atualize as instruções de base (local e Vercel) e exemplos.

