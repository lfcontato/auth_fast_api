Arquivo: docs/_outros/VERCEL.md
Resumo: Guia de deploy/execução na Vercel e local, com dicas de build para Go e exemplos de teste.

Manutenção: mantenha este documento alinhado ao `go.mod`, `vercel.json` e às rotas expostas. Remova qualquer marcador de conflito em caso de merges.

# Execução local (sem Vercel)

```bash
go run ./cmd/server

# saúde
curl -i http://localhost:8080/healthz

# login admin
curl -sS -X POST http://localhost:8080/admin/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"stringst"}'
```

# Deploy na Vercel

Pré‑requisitos
- `vercel` CLI instalado (local do projeto)
- Variáveis de ambiente configuradas (DATABASE_URL, SECRET_KEY, SMTP, etc.)

Baixar variáveis (opcional, recomendado)
```bash
vercel pull --environment=development && vercel env pull .env.development
vercel pull --environment=preview && vercel env pull .env.preview
```

Publicar
```bash
vercel --prod
```

# Testes em produção (Vercel)

Com `vercel.json` atual, os rewrites mapeiam diretamente algumas rotas ao `api/index.go`:
- Sem prefixo: `/healthz`, `/admin`, `/admin/...`
- Com prefixo: `/api`, `/api/...` (equivalente)

Exemplos:
```bash
# Healthcheck
curl -i https://<seu-projeto>.vercel.app/healthz

# Login Admin (sem /api por causa dos rewrites)
curl -sS -X POST https://<seu-projeto>.vercel.app/admin/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"stringst"}'

# Password Recovery
curl -sS -X POST https://<seu-projeto>.vercel.app/admin/auth/password-recovery \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com"}'
```

# Notas de Build (Go)

- O projeto está pinado para Go 1.22 em `go.mod`. Dependências
  (`modernc.org/sqlite`, `pgx`, `x/sys`, `x/sync`) foram fixadas para
  evitar a exigência de Go 1.24 no ambiente da Vercel.
- Evite usar `go mod tidy` no repositório com `node_modules` na raiz. O Go pode
  tentar escanear este diretório e falhar. Sugestões:
  - Não commitar `node_modules` na raiz do módulo Go; ou
  - Rodar builds focados: `go build ./api` (sem `./...`); ou
  - Usar `.vercelignore` para excluir `node_modules` do contexto.

# Execução local via Vercel CLI

```bash
# execução local do runtime vercel
vercel dev

# se preferir via dependência local
npm init -y && npm i -D vercel
npx vercel dev
```
