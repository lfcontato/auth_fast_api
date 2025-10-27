Arquivo: HOWTOUSE_USERS.md
Resumo: Exemplos de consumo das rotas de Usuários e UsersSpaces.

Manutenção: revise estes exemplos após qualquer mudança de rota, parâmetros, códigos de resposta ou regras de autenticação/ACL. Garanta consistência com USERS.md e TOOLS.md. Não inclua checklists ou “próximos passos” aqui — o local canônico para isso é USERS.md (para usuários) e TOOLS.md (para tools).

# Base
- Local: `http://localhost:8080`
- Se estiver em Vercel: prefixe com `/api` se necessário.

# Login do Usuário

```
curl -X POST http://localhost:8080/user/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"usuario","password":"minhasenha"}'
```

Resposta (200):
```
{"success":true,"access_token":"<jwt>","refresh_token":"<opaque>"}
```

# Refresh Token
```
curl -X POST http://localhost:8080/user/auth/token/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

# Verificar Conta (code + password)
```
curl -X POST http://localhost:8080/user/auth/verify \
  -H 'Content-Type: application/json' \
  -d '{"code":"<CODIGO>","password":"<SENHA_ATUAL>"}'
```

# Verificar via Link Público
```
curl "http://localhost:8080/user/auth/verify-link?login=usuario&code=<CODIGO>"
```

# Recuperar Senha
```
curl -X POST http://localhost:8080/user/auth/password-recovery \
  -H 'Content-Type: application/json' \
  -d '{"email":"usuario@exemplo.com"}'
```

# Reenviar Código de Verificação
```
curl -X POST http://localhost:8080/user/auth/verification-code \
  -H 'Content-Type: application/json' \
-d '{"login":"usuario"}'
```

# Criar Usuário (signup)
```
curl -X POST http://localhost:8080/user \
  -H 'Content-Type: application/json' \
  -d '{
    "email":"user@example.com",
    "username":"usuario",
    "password":"MinhaSenha123!",
    "confirm_password":"MinhaSenha123!"
  }'
```

# Criar UsersSpace (requer tools_role=admin)
```
ACCESS_TOKEN="<JWT_DO_LOGIN>"
curl -X POST http://localhost:8080/user/spaces \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Meu Espaço"}'
```

# Listar Meus UsersSpaces
```
ACCESS_TOKEN="<JWT_DO_LOGIN>"
curl -s http://localhost:8080/user/spaces \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

# Fluxo de Testes Rápido (end‑to‑end)

1) Login e capturar tokens
```
LOGIN_RESP=$(curl -s -X POST http://localhost:8080/user/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"usuario","password":"minhasenha"}')
echo "$LOGIN_RESP" | jq .
ACCESS_TOKEN=$(echo "$LOGIN_RESP" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$LOGIN_RESP" | jq -r .refresh_token)
```

2) Refresh
```
curl -s -X POST http://localhost:8080/user/auth/token/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"'"$REFRESH_TOKEN"'"}' | jq .
```

3) Reenviar código de verificação (caso necessário)
```
curl -s -X POST http://localhost:8080/user/auth/verification-code \
  -H 'Content-Type: application/json' \
  -d '{"login":"usuario"}' | jq .
```

4) Verificar conta via código + senha (o código é enviado por e‑mail)
```
curl -s -X POST http://localhost:8080/user/auth/verify \
  -H 'Content-Type: application/json' \
  -d '{"code":"<CODIGO_RECEBIDO>","password":"minhasenha"}' | jq .
```

5) Recuperar senha (gera senha temporária + novo código por e‑mail)
```
curl -s -X POST http://localhost:8080/user/auth/password-recovery \
  -H 'Content-Type: application/json' \
  -d '{"email":"usuario@exemplo.com"}' | jq .
```

6) Verificar conta novamente (após recovery) usando o novo código recebido
```
curl -s -X POST http://localhost:8080/user/auth/verify \
  -H 'Content-Type: application/json' \
  -d '{"code":"<NOVO_CODIGO>","password":"<NOVA_SENHA>"}' | jq .
```
# Notas de campos (Users) — Regra
- `tools_role`: default `guest`; opções: `guest|user|admin|root`.
- `subscription_plan`: default `trial`; opções: `trial|monthly|semiannual|annual|lifetime`.
- `password`: em fluxos de cadastro de usuário (quando presentes), é opcional; o sistema gera automaticamente quando omitida.
