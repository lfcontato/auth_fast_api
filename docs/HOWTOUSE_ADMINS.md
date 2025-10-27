Arquivo: HOWTOUSE_ADMINS.md
Resumo: Exemplos de uso das rotas de administradores, com observações sobre defaults e enumerações.

Manutenção: mantenha alinhado com ADMINS.md e openapi.json. Não incluir checklists aqui.

# Base
- Local: `http://localhost:8080`

# Criar Administrador

```bash
ACCESS="<JWT_ROOT_OU_ADMIN>"
curl -sS -X POST http://localhost:8080/admin \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{
    "email":"novo@dominio.com",
    "username":"novo_admin",
    "system_role":"user",
    "subscription_plan":"trial"
  }' | jq .
```

Notas de campos e defaults (Regra)
- `password`: opcional; se omitida, o sistema gera.
- `system_role`: opcional; default `guest`; enum `guest|user|admin|root`.
- `subscription_plan`: opcional; default `trial`; enum `trial|monthly|semiannual|annual|lifetime`.

Ambiente de teste

- Se o e‑mail informado terminar em `@domain.com`, o envio de e‑mail de criação é suprimido (não enviado), útil para testes.

# Reenviar Código de Verificação (Admin)

```bash
curl -sS -X POST http://localhost:8080/admin/auth/verification-code \
  -H 'Content-Type: application/json' \
  -d '{"login":"root"}' | jq .
```

Notas
- Reaproveita o último código válido (24h por padrão) ou cria um novo e invalida anteriores.
- Rate limit:
  - Por IP: `VERIFY_RESEND_IP_LIMIT`/`VERIFY_RESEND_IP_WINDOW_MINUTES`
  - Por login/e-mail: `VERIFY_RESEND_LOGIN_LIMIT`/`VERIFY_RESEND_LOGIN_WINDOW_MINUTES`

# Alterar Papel
```bash
curl -sS -X PATCH http://localhost:8080/admin/2/system-role \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"system_role":"admin"}' | jq .
```

# Alterar Plano
```bash
curl -sS -X PATCH http://localhost:8080/admin/2/subscription-plan \
  -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d '{"subscription_plan":"semiannual"}' | jq .
```
