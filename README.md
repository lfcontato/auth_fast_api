# 🚀[auth_basics_api](https://auth-basics-api.vercel.app/)
O sistema auth_basics_api utiliza JWT para autenticação, gerencia administradores de forma hierárquica, permite recuperação segura de senha, protege contra brute force. Consolidadando bases arquiteturais que tornam o auth_app seguro, escalável e alinhado a padrões modernos.

## 🔒[Configurar SSH](docs/SSHKEY.md)

Comandos configura chaves ssh no linux em [SSHKEY.md](docs/SSHKEY.md)

## 💻 Criar o projeto

```bash
# CRIAR O PROJETO NA PASTA workspace
poetry new --flat auth_basics_api --name auth_app
cd auth_basics_api

# INICIALIZAR O GIT LOCAL (JÁ FEITO)
git init

# ADICIONAR E FAZER O PRIMEIRO COMMIT (JÁ FEITO)
git add .
git commit -m "feat: initial project setup with Poetry"

# ADICIONAR O REPOSITÓRIO REMOTO
# Certifique-se de que o repositório 'username/auth_basics_api' existe no GitHub.
git remote add origin git@github.com:username/auth_basics_api.git

# RENOMEAR O BRANCH LOCAL PARA 'main'
git branch -M main

# 6. ENVIAR PARA O GITHUB (PUSH)
# O comando '-u origin main' define 'origin/main' como o upstream do seu branch 'main'.
git push -u origin main

```

## 💻 [Ambiente Poetry](docs/POETRY.md)

Comandos iniciais do poetry em: [POETRY.md](docs/POETRY.md)

## 💻 [Dependencias do Projeto](docs/DEPENDENCIES.md)

Dependencias do Projeto em: [DEPENDENCIES.md](docs/DEPENDENCIES.md)

## 💻 [Servidor Uvicorn](docs/UVICORN.md)

Comandos do Uvicorn em: [UVICORN.md](docs/UVICORN.md)

```text
Comando úteis para o vscode:
Aperte F1 (ou Ctrl + Shift + P / Cmd + Shift + P no Mac) para abrir a Paleta de Comandos.
Digite Reload Window (Recarregar Janela) e selecione o comando.
```

```text
/auth_fast_api
├── api/
│   └── index.go          # O Handler que o Vercel executa (ponto de entrada)
├── internal/
│   ├── auth/             # Lógica de JWT e autenticação
│   │   └── auth.go
│   ├── db/               # Lógica de conexão e modelos do DB
│   │   └── db.go
│   └── handlers/         # Lógica de rotas e autorização
│       └── handlers.go
├── go.mod
└── vercel.json           # Para mapear rotas bonitas
```

go mod edit -module=github.com/lfcontato/auth_fast_api
go mod tidy
go run main.go