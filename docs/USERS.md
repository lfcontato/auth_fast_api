Arquivo: docs/USERS.md
Resumo: Rotas e modelo de usuários (login/refresh/verify/recovery) e relação com UsersSpaces. Regra de documentação: sempre listar campos opcionais e seus padrões. Em fluxos de cadastro de usuário (quando presentes), a senha é opcional e gerada automaticamente quando omitida.

Manutenção: mantenha este documento atualizado sempre que alterar rotas, payloads, regras de autenticação/ACL. Este arquivo é o local canônico do checklist e “próximos passos” do recurso de Usuários. Os HOWTOUSE não devem conter checklists — apenas exemplos de consumo.

Navegação: [Admins](ADMINS.md) · [Tools](TOOLS.md) · [Como usar (Users)](HOWTOUSE_USERS.md) · [Como usar (Tools)](HOWTOUSE_TOOLS.md)

# Modelo de Usuário

- Tabela `users`:
  - `id`, `email` (único), `username` (único), `password_hash`.
  - `tools_role`: `guest|user|admin|root` (default: `user`).
  - `subscription_plan`: `trial|monthly|semiannual|annual|lifetime` (default: `trial`).
  - `expires_at`: limite global do plano; tokens são clampados a este limite quando aplicável.
  - `is_verified`: exige verificação antes de login.

- Sessões e verificação:
  - `users_sessions_local`: rotação de refresh em cada refresh.
  - `users_verifications`: códigos únicos com TTL (default 24h).

# JWT de Usuário

- Claims principais:
  - `sub`: `"user|<id>"`
  - `uid`: inteiro com o id do usuário
  - `email`: e‑mail do usuário
  - `user`: `true` (para diferenciar de admins)
  - `sid`: id da sessão
  - `exp`: expiração (Unix)

# Endpoints

- POST `/user/auth/token` – login com `{username,password}` → `access_token` e `refresh_token`.
- POST `/user/auth/token/refresh` – novo par de tokens a partir de `refresh_token` válido.
- POST `/user/auth/verify` – confirma conta via `{code,password}`.
- GET `/user/auth/verify-link?login=&code=` – confirma via link público (por `username` ou `email`).
- POST `/user/auth/password-recovery` – redefine senha e envia código por e‑mail.
- POST `/user/auth/verification-code` – reenvia código de verificação (por `login`).
  - Regras: reaproveita o último código válido; se não houver, gera um novo e invalida códigos anteriores ainda não consumidos.
  - Rate limit:
    - Por IP: `VERIFY_RESEND_IP_LIMIT` por `VERIFY_RESEND_IP_WINDOW_MINUTES` (padrão: herda RECOVERY_IP_*)
    - Por login/e-mail: `VERIFY_RESEND_LOGIN_LIMIT` por `VERIFY_RESEND_LOGIN_WINDOW_MINUTES` (padrão: herda RECOVERY_EMAIL_*)
- POST `/user` – cria usuário: `{ email, username, password, confirm_password }`. Senhas devem coincidir; aplica política de senha. Cria conta `is_verified=false` e envia código de verificação por e‑mail.

Observação (Vercel): ao consumir pela Vercel, use o prefixo `/api` (ex.: `/api/user/auth/token`). Após o próximo deploy, rotas sem `/api` também funcionarão por rewrite.

# UsersSpaces

- Tabela `users_spaces`:
  - `owner_user_id`, `name`, `hash` (único, 32 chars), `created_at`, `updated_at`.
- Rotas atuais:
  - POST `/user/spaces` – criar (requer JWT de usuário e `tools_role=admin`).
  - GET `/user/spaces` – listar espaços do usuário autenticado (onde ele é owner).
- Membership e permissões:
  - POST `/user/spaces/{space_id}/members` – adicionar membro (owner apenas) `{login, role}`.
  - GET `/user/spaces/{space_id}/members` – listar membros (owner apenas).
  - PATCH `/user/spaces/{space_id}/members/{user_id}` – alterar papel (owner apenas).
  - DELETE `/user/spaces/{space_id}/members/{user_id}` – remover membro (owner apenas).

# Próximos Passos (Checklist)
  - [x] Tabelas: `users`, `users_sessions_local`, `users_verifications`.
  - [x] Login/Refresh do usuário: `POST /user/auth/token`, `POST /user/auth/token/refresh`.
  - [x] Verificação: `POST /user/auth/verify`, `GET /user/auth/verify-link`.
  - [x] Recuperação de senha: `POST /user/auth/password-recovery`.
  - [x] Reenvio de código: `POST /user/auth/verification-code`.
  - [x] JWT com claims: `uid`, `email`, `user=true` e clamp por plano.
  - [x] UsersSpaces: tabela `users_spaces` e criação/listagem (`POST/GET /user/spaces`).
  - [x] Membership: adicionar/listar/alterar/remover membros do espaço.
  - [ ] Convites/aceite de membros por link/token (expirável) e saída voluntária.
  - [ ] Transferência de propriedade do espaço (owner → outro admin).
  - [ ] Exclusão/arquivamento de UsersSpace com salvaguardas e cascatas.
  - [ ] Auditoria (logs) e rate limit específico por usuário/space.
  - [ ] Endpoints de perfil do usuário (senha, e-mail) e chaves de API por tool.
  - [ ] Paginação/filtro nas listagens (espaços e membros).
  - [ ] Testes de integração e exemplos adicionais nos HOWTOUSE.

Redirecionamento e links de verificação

- Os e‑mails enviados para criação, reenvio de código e recuperação de senha incluem:
  - Um link “Verificar conta” apontando para `/user/auth/verify-link?login=&code=` (ou `/api/user/...` na Vercel quando a chamada foi para `/api`).
  - O código de verificação em texto no corpo do e‑mail.
- A base do link é definida assim:
  1) Se `ALLOWED_REDIRECT_URIS` estiver configurada e `Origin`/`Referer` da requisição pertencer a essa lista, usa essa origem (frontend).
  2) Caso contrário, usa `PUBLIC_BASE_URL`.
  3) Se também estiver vazia, usa a URL pública da própria API.

Política de senha

- Mínimo de 8 caracteres.
- Se `PASSWORD_POLICY_STRICT=true`, exige maiúscula, minúscula, número e caractere especial.

Ambiente de teste (@domain.com)

- Na criação e no reenvio de código de usuários, se o e‑mail terminar com `@domain.com`, o sistema não envia e‑mail (apenas registra o código no banco). Útil para testes.
