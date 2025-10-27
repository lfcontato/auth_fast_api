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
