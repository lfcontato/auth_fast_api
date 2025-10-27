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

ALLOWED_REDIRECT_URIS

- Lista separada por vírgula de origens permitidas (scheme + host, com porta se necessário), por exemplo:
  - `ALLOWED_REDIRECT_URIS="https://app.seu-dominio.app, https://localhost:3000"`
- Se definido e a requisição tiver `Origin` ou `Referer` igual a uma dessas origens, os links de verificação enviados por e‑mail usarão essa origem como base.
- Se não houver correspondência (ou a lista estiver vazia), usa `PUBLIC_BASE_URL`; se vazia, usa a URL pública da própria API.
