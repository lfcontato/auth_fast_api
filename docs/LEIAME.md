Para construir o codigo, use estes arquivos, da pasta DOCS como fonte
principalmente o PROMPT_DESENVOLVIMENTO_CONTINUO.md


Variáveis de ambiente importantes

- `DATABASE_URL`: URL do banco (Postgres/SQLite)
- `SECRET_KEY`: chave JWT
- `LOG_LEVEL`: nível de log
- `EMAIL_*`: configurações SMTP
- `PUBLIC_BASE_URL`: base pública (frontend) para montar links
- `ALLOWED_REDIRECT_URIS`: origens autorizadas para redireciono
- `VERIFY_RESEND_IP_LIMIT` / `VERIFY_RESEND_IP_WINDOW_MINUTES`: rate limit de reenvio por IP (defaults herdam RECOVERY_IP_*)
- `VERIFY_RESEND_LOGIN_LIMIT` / `VERIFY_RESEND_LOGIN_WINDOW_MINUTES`: rate limit de reenvio por login/e-mail (defaults herdam RECOVERY_EMAIL_*)
- `EXPOSE_DB_CONFIG`: quando `true`, expõe `/api/healthz/db-config` com informações sanitizadas do DB (sem senha). Padrão: `false`. Use apenas temporariamente para diagnóstico.

ALLOWED_REDIRECT_URIS e redirect_uri (payload)

- Lista separada por vírgula de origens permitidas (scheme + host, com porta se necessário), por exemplo:
  - `ALLOWED_REDIRECT_URIS="https://app.seu-dominio.app, https://localhost:3000"`
- Precedência para montar a base dos links em e‑mails (verificação/recuperação):
  1) Se o payload enviar `redirect_uri` (ex.: no `POST /user` ou `POST /admin`), essa URL é usada como base.
  2) Caso contrário, se `ALLOWED_REDIRECT_URIS` estiver definida, usa a primeira origem válida da lista.
  3) Caso contrário, usa `PUBLIC_BASE_URL`.
  4) Se ainda vazio, usa a URL pública da própria API (deduzida de `X-Forwarded-*` ou `Host`).
- Observação: a partir desta mudança, quando `ALLOWED_REDIRECT_URIS` estiver definida, o e‑mail não depende mais de `Origin/Referer` para escolher a base; ele adotará a primeira origem válida da lista, a menos que o `redirect_uri` seja enviado no payload.
- Formatos aceitos para Postgres em `*_DATABASE_URL`:
  - URL (recomendada): `postgresql://user:senha@host:5432/db?sslmode=require`
    - Se a senha tiver caracteres especiais, faça percent-encode (ex.: `#` → `%23`, `@` → `%40`, `!` → `%21`).
  - Formato libpq (sem encode): `host=... port=5432 dbname=... user=... password=... sslmode=require`
    - Esse formato aceita senha “crua” (sem precisar encodar). Mantenha tudo entre aspas no `.env`.

- Variáveis relacionadas: `DATABASE_URL`, `FACIENDUM_DATABASE_URL`, `AUTOMATA_DATABASE_URL` aceitam ambos formatos acima.
