# Baixar as Variáveis de Ambiente (Opcional, mas Recomendado)

```bash
vercel pull --environment=development
vercel env pull .env.development
```

# Com o terminal no diretório do projeto dev, use o comando dev:
```bash
vercel dev
```

# Com o terminal no diretório do projeto, use o comando dev:
```bash
vercel --prod
```

# Com o terminal no diretório local do projeto, use o comando go:
```bash
go run ./cmd/server
```




A Vercel é uma empresa americana com sede nos EUA, mas sua plataforma de hospedagem na nuvem não tem uma "localização" física única, pois opera em uma infraestrutura global de servidores distribuídos pela AWS (Amazon Web Services)

Você pode ver a região do seu Vercel verificando o cabeçalho x-vercel-id da sua implantação, ou no arquivo vercel.json se você configurou funções serverless. Outra forma é checar a variável de ambiente VERCEL_REGION no ambiente de build. 


https://vercel.com/luisfernandopereiragmailcoms-projects/auth-basics-api/settings/functions#function-region
Washington, D.C., USA (East) - us-east-1 - iad1

vercel dev
Testes:
curl -i http://localhost:3000/healthz
curl -i http://localhost:3000/api/healthz (também funciona por compatibilidade)
Se ainda der erro de permissão no builder global

Use o CLI local ao projeto (evita gravar em /usr/lib):
npm init -y
npm i -D vercel
npx vercel dev
Ou rode local sem Vercel

go run ./cmd/server
curl -i http://localhost:8080/healthz
curl -i https://auth-fast-api.vercel.app/healthz
-- assim funciona


curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"stringst"}'
curl -sS -X POST https://auth-fast-api.vercel.app/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"stringst"}'

rodei
npm init -y
npm i -D vercel
