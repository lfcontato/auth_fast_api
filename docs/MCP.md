MCP Server para a Auth Fast API

Resumo
- Este servidor MCP (Model Context Protocol) expõe uma ferramenta única para que um cliente/IA faça chamadas HTTP à sua API usando um token MCP (PAT) com Bearer.
- Arquivo do servidor: `mcp/server.mjs`.
- Uso típico: clientes MCP (ex.: OpenAI Desktop/VS Code) conectam via stdio e pedem em linguagem natural; o cliente decide quando chamar a ferramenta.

Requisitos
- Node.js 18+ (para ESM e fetch/undici).
- Variáveis de ambiente:
  - `AUTH_API_BASE_URL` – Base da API (produção Vercel: `https://auth-fast-api.vercel.app/api`).
  - `AUTH_API_PAT` – Token MCP (PAT) criado via `POST /admin/mcp/token`.

Instalação
1) Instale dependências:
   - `npm i`
   - Se necessário: `npm i @modelcontextprotocol/sdk undici`
2) Configure variáveis de ambiente (exemplo Linux/macOS):
   - `export AUTH_API_BASE_URL="https://auth-fast-api.vercel.app/api"`
   - `export AUTH_API_PAT="<SEU_PAT>"`

Execução
- Local: `npm run mcp:server`
- O processo roda por stdio (fica aguardando um cliente MCP conectar). Para uso manual, apenas verifique logs iniciais; a interação ocorre por um cliente compatível.

Ferramenta Disponível
- Nome: `auth_api.request`
- Descrição: Faz uma chamada HTTP à sua API injetando `Authorization: Bearer <PAT>`.
- Parâmetros (JSON):
  - `method` (string; GET|POST|PUT|PATCH|DELETE)
  - `path` (string; deve começar com `/`. Em Vercel, inclua `/api` no caminho ou já defina na base URL.)
  - `query` (objeto; opcional)
  - `headers` (objeto; opcional)
  - `body` (objeto ou string; opcional)
  - `contentType` (string; opcional; default `application/json` quando há body)

Exemplos de Uso (conceituais)
- Listar admins verificados:
  - NL: “Liste administradores verificados.”
  - A IA pode chamar: `{ "method":"GET", "path":"/admin", "query": { "verified": true } }`
- Criar token MCP:
  - NL: “Crie um token de API para n8n com 30 dias.”
  - Chamada: `{ "method":"POST", "path":"/admin/mcp/token", "body": { "name": "n8n", "ttl_hours": 720 } }`

Integração com Clientes MCP
- OpenAI Desktop/VS Code (ou outros clientes MCP):
  - Configure um provedor MCP “stdio” cujo comando seja `node mcp/server.mjs` (ou `npm run mcp:server`).
  - Garanta que `AUTH_API_PAT` e `AUTH_API_BASE_URL` estão no ambiente do processo.
- Produção: `AUTH_API_BASE_URL=https://auth-fast-api.vercel.app/api` (o prefixo `/api` é obrigatório nas rotas).

Boas Práticas de Segurança
- Privilégio mínimo: gere o PAT a partir de um admin com o `system_role` adequado.
- TTL curto e rotação periódica de tokens.
- Nunca exponha o PAT em apps clientes públicos; injete-o no servidor MCP (lado server) ou via proxy.
- O PAT herda permissões e expiração da conta; respeite a hierarquia das rotas.

Referências úteis
- Schema OpenAPI local: `openapi.json`
- Guia de uso da API e tokens: `HOWTOUSE.md` (seção “Tokens de API (para n8n/MCP)”).

Seção: n8n “AI Agent” (casos de uso)
- Objetivo: permitir que o agente de IA do n8n chame a API descrevendo a intenção em linguagem natural, usando o PAT.
- Pré‑requisitos: PAT criado via `POST /admin/mcp/token` e URL base de produção.
- Passos rápidos:
  - Crie um Workflow no n8n e adicione o nó “AI Agent”.
  - Em “Tools” do AI Agent, adicione um “HTTP Request” como ferramenta disponível.
  - Configure o HTTP Request:
    - Base URL: `https://auth-fast-api.vercel.app/api`
    - Authentication: Bearer Token → referência segura ao PAT (credencial/secret) ou variável `{{ $env.AUTH_API_PAT }}`.
    - Default headers: `Accept: application/json`
  - Contexto: opcionalmente, anexe o arquivo `openapi.json` ao prompt do agente para melhor grounding.

Exemplo cURL (equivalente ao que o AI Agent executa)
```bash
# Defina seu PAT (token MCP criado via /admin/mcp/token)
PAT="<SEU_PAT>"

# Listar administradores (primeiros 20)
curl -sS -X GET \
  'https://auth-fast-api.vercel.app/api/admin?limit=20&offset=0' \
  -H "Authorization: Bearer ${PAT}" \
  -H 'Accept: application/json'

# (Opcional) Obter o OpenAPI para o agente conhecer os endpoints
curl -sS -X GET 'https://auth-fast-api.vercel.app/api/openapi.json' \
  -H 'Accept: application/json'
```

Casos de teste
- Listar administradores (primeiros 20)
  - Intenção: “Liste os administradores (primeiros 20).”
  - Tool call esperado: GET `/admin?limit=20&offset=0`
- Criar PAT para integração n8n
  - Intenção: “Crie um token de API de 30 dias chamado n8n.”
  - Tool call: POST `/admin/mcp/token` body `{ "name": "n8n", "ttl_hours": 720 }`
- Obter OpenAPI
  - Intenção: “Baixe o OpenAPI para saber os endpoints.”
  - Tool call: GET `/openapi.json`

n8n – MCP Client (quando disponível)
- Objetivo: conectar o AI Agent do n8n diretamente ao MCP por stdio, usando o servidor `mcp/server.mjs`.
- Requisito: o nó AI Agent deve oferecer “MCP Client” como tipo de Tool. Se não estiver disponível, use o HTTP Request conforme seção anterior.
- Configuração:
  - Execute o servidor MCP localmente: `npm run mcp:server`.
  - No nó AI Agent, em Tools → Add Tool → selecione “MCP Client”. Em “Add MCP Server”, configure:
    - Transport/Type: `stdio`
    - Command: `node`
    - Args: `mcp/server.mjs`
    - Working Directory: caminho do repositório onde está a pasta `mcp/`
    - Environment:
      - `AUTH_API_BASE_URL=https://auth-fast-api.vercel.app/api`
      - `AUTH_API_PAT=<SEU_PAT>`
  - Salve o workflow e rode uma execução de teste.
- Uso:
  - O agente deve listar `auth_api.request` como tool MCP disponível.
  - Dê instruções em linguagem natural (ex.: “Liste os administradores, primeiros 20”) e permita a chamada quando solicitado.
- Observações:
  - Em ambientes Docker/Cloud, o transporte `stdio` pode não estar acessível; prefira o tool HTTP Request.
  - Armazene o PAT em credenciais/variáveis seguras do n8n, não no prompt.
