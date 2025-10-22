# Baixar as Variáveis de Ambiente (Opcional, mas Recomendado)

```bash
vercel pull --environment=development
vercel env pull .env.development

vercel pull --environment=preview
vercel env pull .env.preview
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


```bash
# local
go run ./cmd/server 

# -- assim funciona
curl -i http://localhost:8080/healthz

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Sun, 19 Oct 2025 16:55:44 GMT
Content-Length: 57
{"ok":true,"service":"auth_fast_api","status":"healthy"} -->

# -- assim funciona
curl -sS -X POST http://localhost:8080/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"stringst"}' 

{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjA4OTQ3NzksInNpZCI6IjM5YWI4ZTFmLWY3NGYtNGE5My05NzU2LWNjOWE3ZDczOGU2YyIsInNybyI6InJvb3QiLCJzdWIiOiJhZG1pbnwxIiwid3NzIjp7fX0.RWEHh2Umy_g9oRQmn75wjrcNmLQIDV3W2k9jbXPnw-g","refresh_token":"34f62c88851441c127cea461d5c1fd9c70854914de261d0c6ef4fb2958450758","success":true}


# na vercel

# -- assim funciona
curl -i https://auth-fast-api.vercel.app/healthz

HTTP/2 200 
age: 0
cache-control: public, max-age=0, must-revalidate
content-type: application/json; charset=utf-8
date: Sun, 19 Oct 2025 16:58:54 GMT
server: Vercel
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-vercel-cache: MISS
x-vercel-id: gru1::iad1::zbqbh-1760893134194-354c4829fe19
content-length: 57

{"ok":true,"service":"auth_fast_api","status":"healthy"}


# -- assim funciona
curl -sS -X POST https://auth-fast-api.vercel.app/admin/auth/token -H 'Content-Type: application/json' -d '{"username":"admin","password":"stringst"}'

A server error has occurred

FUNCTION_INVOCATION_FAILED

gru1::rhcj4-1760893167938-264f5f8cb8b0

# -- assim funciona envia o e-mail
curl -sS -X POST http://localhost:8080/admin/auth/password-recovery -H 'Content-Type: application/json' -d '{"email":"luis.fernando.pereira.procempa@gmail.com"}'
{"sent":true,"success":true}

# -- assim funciona envia o e-mail / reposta dá ok mas nao envia
curl -sS -X POST https://auth-fast-api.vercel.app/admin/auth/password-recovery -H 'Content-Type: application/json' -d '{"email":"luis.fernando.pereira.procempa@gmail.com"}'
{"sent":true,"success":true}



```





rodei
npm init -y
npm i -D vercel
