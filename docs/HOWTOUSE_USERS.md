Arquivo: HOWTOUSE_USERS.md
Resumo: Exemplos de consumo das rotas de Usuários e UsersSpaces.

Manutenção: revise estes exemplos após qualquer mudança de rota, parâmetros, códigos de resposta ou regras de autenticação/ACL. Garanta consistência com USERS.md e TOOLS.md. Não inclua checklists ou “próximos passos” aqui — o local canônico para isso é USERS.md (para usuários) e TOOLS.md (para tools).

# Base
- Local: `http://localhost:8080`
- Vercel: prefira `https://auth-fast-api.vercel.app/api/...`
  - Observação: após o próximo deploy, `/user/...` sem `/api` também funcionará.

# Login do Usuário

```
curl -X POST http://localhost:8080/user/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"usuario","password":"MinhaSenha123!"}'
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

Notas:
- Reaproveita o último código válido (24h por padrão). Se não houver, gera um novo e invalida anteriores não consumidos.
- Rate limit:
  - Por IP: `VERIFY_RESEND_IP_LIMIT`/`VERIFY_RESEND_IP_WINDOW_MINUTES` (default herda RECOVERY_IP_*)
  - Por login/e-mail: `VERIFY_RESEND_LOGIN_LIMIT`/`VERIFY_RESEND_LOGIN_WINDOW_MINUTES` (default herda RECOVERY_EMAIL_*)

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

# E-mails de verificação
- O e‑mail de boas‑vindas envia um código e um link de verificação (botão “Verificar conta”).
- A base do link é escolhida assim:
  1) Se `ALLOWED_REDIRECT_URIS` estiver definida e a requisição tiver `Origin/Referer` que bata com a lista, usa essa origem (frontend).
  2) Senão, usa `PUBLIC_BASE_URL`.
  3) Se vazio, usa a URL pública da própria API.
- Em Vercel, se a chamada for feita para `/api/...`, o link conterá `/api` para garantir funcionamento.
- Ambiente de teste: ao criar usuário com e‑mail terminando em `@domain.com`, o sistema não enviará e‑mail (apenas grava o código). Use os endpoints de verificação para completar o fluxo.
 - Em ambiente de teste, o reenvio para e‑mails `@domain.com` também não envia e‑mail; o código fica disponível via banco e pode ser usado pelos endpoints de verificação.

# Notas de campos (Users)
- `tools_role`: default `user`.
- `subscription_plan`: default `trial`.
- `password`: mínima de 8; se `PASSWORD_POLICY_STRICT=true`, precisa ter maiúscula, minúscula, número e especial.
